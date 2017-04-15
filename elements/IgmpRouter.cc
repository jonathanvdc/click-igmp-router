#include "IgmpRouter.hh"

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include "IgmpMessage.hh"
#include "IgmpMessageManip.hh"
#include "IgmpRouterFilter.hh"

CLICK_DECLS
IgmpRouter::IgmpRouter()
    : filter(this, true), query_schedule(this)
{
}

IgmpRouter::~IgmpRouter()
{
}

int IgmpRouter::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (cp_va_kparse(conf, this, errh, "ADDRESS", cpkM, cpIPAddress, &address, cpEnd) < 0)
        return -1;

    init_startup_queries();

    return 0;
}

void IgmpRouter::init_startup_queries()
{
    // Keep track of the number of remaining startup general queries. See the SPEC INTERPRATION
    // comment in 'IgmpRouter::SendPeriodicGeneralQuery::operator()() const' for an explanation.
    startup_general_queries_remaining = filter.get_router_variables().get_startup_query_count();

    general_query_timer = CallbackTimer<SendPeriodicGeneralQuery>(this);
    general_query_timer.initialize(this);
    general_query_timer.schedule_after_csec(
        filter.get_router_variables().get_startup_query_interval());
}

void IgmpRouter::push(int port, Packet *packet)
{
    if (port == 0)
    {
        auto ip_header = (click_ip *)packet->data();
        if (filter.is_listening_to(ip_header->ip_dst, ip_header->ip_src))
        {
            output(1).push(packet);
        }
        else
        {
            output(2).push(packet);
        }
    }
    else
    {
        assert(port == 1);
        handle_igmp_packet(packet);
    }
}

void IgmpRouter::handle_igmp_packet(Packet *packet)
{
    click_chatter(
        "Received IGMP packet with type %d at router",
        (int)get_igmp_message_type(packet->data()));

    if (is_igmp_membership_query(packet->data()))
    {
        // Handle IGMP membership queries.
        auto data_ptr = packet->data();
        handle_igmp_membership_query(IgmpMembershipQuery::read(data_ptr), packet->ip_header()->ip_src);
        packet->kill();
        return;
    }

    if (!is_igmp_v3_membership_report(packet->data()))
    {
        // Silently ignore non-membership report--, non-query--messages.
        packet->kill();
        return;
    }

    auto data_ptr = packet->data();
    auto report = IgmpV3MembershipReport::read(data_ptr);
    for (const auto &group : report.group_records)
    {
        auto group_string = group.to_string();
        click_chatter("Received at router: %s", group_string.c_str());
        IgmpFilterRecord record;
        switch (group.type)
        {
        case IgmpV3GroupRecordType::ModeIsInclude:
        case IgmpV3GroupRecordType::ChangeToIncludeMode:
            record.filter_mode = IgmpFilterMode::Include;
            break;
        case IgmpV3GroupRecordType::ModeIsExclude:
        case IgmpV3GroupRecordType::ChangeToExcludeMode:
            record.filter_mode = IgmpFilterMode::Exclude;
            break;
        default:
            // Ignore group records with unknown types.
            click_chatter("Found IGMP group record with unknown type %d", (int)group.type);
            continue;
        }
        record.source_addresses = group.source_addresses;

        auto old_record_ptr = filter.get_record(group.multicast_address);
        bool was_exclude = old_record_ptr != nullptr && old_record_ptr->filter_mode == IgmpFilterMode::Exclude;

        // Update the filter's state.
        filter.receive_current_state_record(group.multicast_address, record);

        // If the filter record was in EXCLUDE mode and we received a TO_IN group record,
        // then we need to generate IGMP group-specific queries.
        if (was_exclude && group.type == IgmpV3GroupRecordType::ChangeToIncludeMode)
        {
            if (other_querier_present)
            {
                // We're not supposed to transmit requests if we're not the elected querier,
                // so let's just refrain from doing that.
                packet->kill();
                return;
            }

            // According to the spec:
            //
            //
            //     When a table action "Send Q(G)" is encountered, then the group timer
            //     must be lowered to LMQT. The router must then immediately send a
            //     group specific query as well as schedule [Last Member Query Count -
            //     1] query retransmissions to be sent every [Last Member Query
            //     Interval] over [Last Member Query Time].
            //
            //     When transmitting a group specific query, if the group timer is
            //     larger than LMQT, the "Suppress Router-Side Processing" bit is set in
            //     the query message.
            //
            //
            // The reduced version of the spec that I have to implement requires a "Send Q(G)"
            // on every table entry.

            // Lower the group timer to LMQT.
            auto record_ptr = filter.get_record(group.multicast_address);
            if (record_ptr != nullptr)
            {
                record_ptr->timer.schedule_after_csec(
                    filter.get_router_variables().get_last_member_query_time());
            }

            // Send one group-specific query right away and schedule more for later.
            SendGroupSpecificQuery event{this, group.multicast_address};

            // Transmit a group-specific query.
            event();

            // Schedule group-specific queries.
            uint32_t delta_csec = 0;
            for (unsigned int i = 0; i < filter.get_router_variables().get_last_member_query_count() - 1; i++)
            {
                delta_csec += filter.get_router_variables().get_last_member_query_interval();
                query_schedule.schedule_after_csec(delta_csec, event);
            }
        }
    }
    packet->kill();
}

void IgmpRouter::handle_igmp_membership_query(const IgmpMembershipQuery &query, const IPAddress &source_address)
{
    // The spec says the following about membership query handling for routers:
    //
    //
    //     6.6. Action on Reception of Queries
    //
    //     6.6.1. Timer Updates
    //
    //     When a router sends or receives a query with a clear Suppress
    //     Router-Side Processing flag, it must update its timers to reflect the
    //     correct timeout values for the group or sources being queried. The
    //     following table describes the timer actions when sending or receiving
    //     a Group-Specific or Group-and-Source Specific Query with the Suppress
    //     Router-Side Processing flag not set.
    //
    //         Query      Action
    //         -----      ------
    //         Q(G)       Group Timer is lowered to LMQT
    //
    //     When a router sends or receives a query with the Suppress Router-Side
    //     Processing flag set, it will not update its timers.
    //
    //     6.6.2. Querier Election
    //
    //     IGMPv3 elects a single querier per subnet using the same querier
    //     election mechanism as IGMPv2, namely by IP address. When a router
    //     receives a query with a lower IP address, it sets the Other-Querier-
    //     Present timer to Other Querier Present Interval and ceases to send
    //     queries on the network if it was the previously elected querier.
    //     After its Other-Querier Present timer expires, it should begin
    //     sending General Queries.
    //
    //     If a router receives an older version query, it MUST use the oldest
    //     version of IGMP on the network. For a detailed description of
    //     compatibility issues between IGMP versions see section 7.

    // Update the timers if the S-flag is not set.
    if (query.is_group_specific_query() && !query.suppress_router_side_processing)
    {
        auto record_ptr = filter.get_record(query.group_address);
        if (record_ptr != nullptr)
        {
            record_ptr->timer.schedule_after_csec(
                filter.get_router_variables().get_last_member_query_time());
        }
    }

    // Check if the our IP address is smaller than the other router's. If so,
    // then we need to go quiet.
    if (ntohs(address.addr()) < ntohs(source_address.addr()))
    {
        // This meaning of this part of the spec is not abundantly clear:
        //
        //     [...] and ceases to send queries on the network if it was
        //     the previously elected querier. After its Other-Querier Present
        //     timer expires, it should begin sending General Queries.
        //
        // Specifically, it does not answer the following questions:
        //
        //     1. When the querier starts to transmit General Queries, should it
        //        do so as if it was in 'startup' mode? The phrasing of
        //        "it should begin sending General Queries" seems to hint that
        //        this is the case.
        //
        //     2. Should the querier continue to schedule queries while it is not
        //        the elected querier and simply not transmit them? Or should
        //        the scheduling of queries be disabled altogether?
        //
        //        The difference between these approaches is observable: if the
        //        querier schedules a batch of queries and becomes elected querier
        //        halfway through the batch's schedule, then part of the batch
        //        will still be transmitted.
        //
        // SPEC INTERPRETATION:
        //
        //     1. Yes, we should activate 'startup' mode.
        //
        //     2. We will clear our schedule and stop the querier from scheduling
        //        new queries until it becomes the elected querier again.
        //
        //        This is arguably a more complicated interpretation than simply
        //        preventing transmission and it's also a less verbatim way of
        //        reading the spec, but I believe it to be the most sane approach.

        other_querier_present = true;

        general_query_timer.unschedule();
        query_schedule.clear();

        other_querier_present_timer = CallbackTimer<OtherQuerierGone>(this);
        other_querier_present_timer.initialize(this);
        other_querier_present_timer.schedule_after_csec(
            filter.get_router_variables().get_other_querier_present_interval());
    }

    // Oh, and here's a carefully-hidden part of the spec:
    //
    //     [...]
    //     Routers adopt the QRV value from the most
    //     recently received Query as their own [Robustness Variable] value,
    //     unless that most recently received QRV was zero, in which case the
    //     receivers use the default [Robustness Variable] value specified in
    //     section 8.1 or a statically configured value.
    //
    // But it leaves a relatively important question unanswered: what
    // happens to the 'startup_query_count' and 'last_member_query_count'
    // variables? Their _defaults_ are derived from the robustness variable.
    // Should they too change when the robustness variable is changed?
    //
    // SPEC INTERPRETATION: No. The spec does not mandate this (by neglecting to
    // mention it), so doing it anyway would not comply with the spec. Default
    // values are computed at configure-time and are then of no more consequence.
    if (query.robustness_variable != 0)
    {
        filter.get_router_variables().get_robustness_variable() = query.robustness_variable;
    }
}

void IgmpRouter::OtherQuerierGone::operator()() const
{
    // The spec is somewhat... terse about what happens when the Other-Querier
    // Present timer expires:
    //
    //     After its Other-Querier Present timer expires, it should begin
    //     sending General Queries.
    //
    // SPEC INTERPRETATION: we will re-initialize the startup period for general
    // queries once the Other-Querier Present timer expires. We will also set
    // 'other_querier_present' to false.

    elem->other_querier_present = false;
    elem->init_startup_queries();
}

void IgmpRouter::transmit_membership_query(const IgmpMembershipQuery &query)
{
    // Create the packet.
    size_t tailroom = 0;
    size_t packetsize = query.get_size();
    size_t headroom = sizeof(click_ether) + sizeof(click_ip);
    WritablePacket *packet = Packet::make(headroom, 0, packetsize, tailroom);
    if (packet == 0)
        return click_chatter("cannot make packet!");

    // Fill it with data.
    auto data_ptr = packet->data();
    query.write(data_ptr);

    // Set its destination IP.
    packet->set_dst_ip_anno(all_systems_multicast_address);

    // Push it out.
    output(0).push(packet);
}

void IgmpRouter::SendGroupSpecificQuery::operator()() const
{
    click_chatter("IGMP router: querying multicast group %s", group_address.unparse().c_str());

    IgmpMembershipQuery query;
    // According to the spec:
    //
    //     The Last Member Query Interval is the Max Response Time used to
    //     calculate the Max Resp Code inserted into Group-Specific Queries sent
    //     in response to Leave Group messages.
    query.max_resp_time = elem->filter.get_router_variables().get_last_member_query_interval();

    // Set the query's group address.
    query.group_address = group_address;

    // Spec says:
    //
    //     When transmitting a group specific query, if the group timer is
    //     larger than LMQT, the "Suppress Router-Side Processing" bit is set in
    //     the query message.
    auto record_ptr = elem->filter.get_record(group_address);
    auto lmqt = elem->filter.get_router_variables().get_last_member_query_time();
    if (record_ptr->timer.scheduled() && record_ptr->timer.remaining_time_csec() > lmqt)
    {
        query.suppress_router_side_processing = true;
    }

    query.robustness_variable = elem->filter.get_router_variables().get_robustness_variable();

    query.query_interval = elem->filter.get_router_variables().get_query_interval();

    // Transmit the query.
    elem->transmit_membership_query(query);
}

void IgmpRouter::SendPeriodicGeneralQuery::operator()() const
{
    // IGMP routers should send periodic general queries, but the spec isn't abundantly
    // clear on when and how that should happen. What little information the spec holds
    // is scattered across various chapters.
    //
    // 6.1. Conditions for IGMP Queries
    //
    //     Multicast routers send General Queries periodically to request group
    //     membership information from an attached network. These queries are
    //     used to build and refresh the group membership state of systems on
    //     attached networks. Systems respond to these queries by reporting
    //     their group membership state (and their desired set of sources) with
    //     Current-State Group Records in IGMPv3 Membership Reports.
    //
    //     [...]
    //
    // 8.2. Query Interval
    //
    //     The Query Interval is the interval between General Queries sent by
    //     the Querier. Default: 125 seconds.
    //
    //     By varying the [Query Interval], an administrator may tune the number
    //     of IGMP messages on the network; larger values cause IGMP Queries to
    //     be sent less often.
    //
    // 8.3. Query Response Interval
    //
    //     The Max Response Time used to calculate the Max Resp Code inserted
    //     into the periodic General Queries. Default: 100 (10 seconds)
    //
    //     By varying the [Query Response Interval], an administrator may tune
    //     the burstiness of IGMP messages on the network; larger values make
    //     the traffic less bursty, as host responses are spread out over a
    //     larger interval. The number of seconds represented by the [Query
    //     Response Interval] must be less than the [Query Interval].
    //
    // 8.6. Startup Query Interval
    //
    //     The Startup Query Interval is the interval between General Queries
    //     sent by a Querier on startup. Default: 1/4 the Query Interval.
    //
    // That final paragraph is especially confusing: what does it mean for a Querier
    // to be in 'startup' mode? The next section seems to shed some light on that.
    //
    // 8.7. Startup Query Count
    //
    //     The Startup Query Count is the number of Queries sent out on startup,
    //     separated by the Startup Query Interval. Default: the Robustness
    //     Variable.
    //
    // SPEC INTERPRETATION: we will send out [Startup Query Count] *General*
    // Queries with an interval of [Startup Query Interval] between them.
    // To do so, we maintain a counter ('startup_general_queries_remaining') which
    // is set to the [Startup Query Count] at configure-time and is decremented
    // on every 'startup' General Query send. Once the counter reaches zero,
    // the [Query Interval] is used to space General Queries instead.

    // Construct a General Query.
    IgmpMembershipQuery query;
    query.max_resp_time = elem->filter.get_router_variables().get_query_response_interval();
    query.robustness_variable = elem->filter.get_router_variables().get_robustness_variable();
    query.query_interval = elem->filter.get_router_variables().get_query_interval();

    // Transmit the Query.
    elem->transmit_membership_query(query);

    // Reschedule the General Query timer.
    auto interval = elem->filter.get_router_variables().get_query_interval();
    if (elem->startup_general_queries_remaining > 0)
    {
        elem->startup_general_queries_remaining--;
        interval = elem->filter.get_router_variables().get_startup_query_interval();
    }
    elem->general_query_timer.reschedule_after_csec(interval);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IgmpRouter)

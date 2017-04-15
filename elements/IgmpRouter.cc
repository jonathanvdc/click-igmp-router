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
    : filter(this, false)
{
}

IgmpRouter::~IgmpRouter()
{
}

int IgmpRouter::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (cp_va_kparse(conf, this, errh, cpEnd) < 0)
        return -1;

    // Keep track of the number of remaining startup general queries. See the SPEC INTERPRATION
    // comment in 'IgmpRouter::SendPeriodicGeneralQuery::operator()() const' for an explanation.
    startup_general_queries_remaining = filter.get_router_variables().get_startup_query_count();

    general_query_timer = CallbackTimer<SendPeriodicGeneralQuery>(this);
    general_query_timer.initialize(this);
    general_query_timer.schedule_after_csec(
        filter.get_router_variables().get_startup_query_interval());
    return 0;
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

    if (!is_igmp_v3_membership_report(packet->data()))
    {
        // Silently ignore non-membership report--messages.
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

        // Update the filter's state.
        filter.receive_current_state_record(group.multicast_address, record);

        // If the group indicated a change, then we need to generate IGMP queries.
        if (group.is_change())
        {
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

            auto record_ptr = filter.get_record(group.multicast_address);
            if (record_ptr != nullptr)
            {
                record_ptr->timer.schedule_after_csec(
                    filter.get_router_variables().get_last_member_query_time());
            }

            // Query the given multicast group for its state.
            query_multicast_group(group.multicast_address);
        }
    }
    packet->kill();
}

void IgmpRouter::query_multicast_group(const IPAddress &multicast_address)
{
    click_chatter("IGMP router: querying multicast group %s", multicast_address.unparse().c_str());

    IgmpMembershipQuery query;
    // According to the spec:
    //
    //     The Last Member Query Interval is the Max Response Time used to
    //     calculate the Max Resp Code inserted into Group-Specific Queries sent
    //     in response to Leave Group messages.
    query.max_resp_time = filter.get_router_variables().get_last_member_query_interval();

    // Set the query's group address.
    query.group_address = multicast_address;

    // Spec says:
    //
    //     When transmitting a group specific query, if the group timer is
    //     larger than LMQT, the "Suppress Router-Side Processing" bit is set in
    //     the query message.
    auto record_ptr = filter.get_record(multicast_address);
    auto lmqt = filter.get_router_variables().get_last_member_query_time();
    if (record_ptr->timer.scheduled() && record_ptr->timer.remaining_time_csec() > lmqt)
    {
        query.suppress_router_side_processing = true;
    }

    query.robustness_variable = filter.get_router_variables().get_robustness_variable();

    query.query_interval = filter.get_router_variables().get_query_interval();

    // Transmit the query.
    transmit_membership_query(query);
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
    // TODO: SPEC INTERPRETATION: we will send out [Startup Query Count] *General*
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

#include "IgmpGroupMember.hh"

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include "IgmpMessage.hh"
#include "IgmpMessageManip.hh"
#include "IgmpMemberFilter.hh"

CLICK_DECLS
IgmpGroupMember::IgmpGroupMember()
{
}

IgmpGroupMember::~IgmpGroupMember()
{
}

int IgmpGroupMember::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (cp_va_kparse(conf, this, errh, cpEnd) < 0)
        return -1;
    return 0;
}

void IgmpGroupMember::push_listen(const IPAddress &multicast_address, const IgmpFilterRecord &record)
{
    filter.listen(multicast_address, record);
    click_chatter("IGMP group member: changing mode for %s", multicast_address.unparse().c_str());

    IgmpV3MembershipReport report;
    report.group_records.push_back(IgmpV3GroupRecord(multicast_address, record, true));

    size_t tailroom = 0;
    size_t packetsize = report.get_size();
    size_t headroom = sizeof(click_ether) + sizeof(click_ip);
    WritablePacket *packet = Packet::make(headroom, 0, packetsize, tailroom);
    if (packet == 0)
        return click_chatter("cannot make packet!");

    auto data_ptr = packet->data();
    report.write(data_ptr);

    packet->set_dst_ip_anno(report_multicast_address);

    output(0).push(packet);
}

int IgmpGroupMember::join(const String &conf, Element *e, void *, ErrorHandler *errh)
{
    IgmpGroupMember *self = (IgmpGroupMember *)e;
    IPAddress to;
    if (cp_va_kparse(conf, self, errh, "TO", cpkM, cpIPAddress, &to, cpEnd) < 0)
        return -1;

    click_chatter("IGMP group member: join %s", to.unparse().c_str());
    self->push_listen(to, create_igmp_join_record());
    return 0;
}

int IgmpGroupMember::leave(const String &conf, Element *e, void *, ErrorHandler *errh)
{
    IgmpGroupMember *self = (IgmpGroupMember *)e;
    IPAddress to;
    if (cp_va_kparse(conf, self, errh, "TO", cpkM, cpIPAddress, &to, cpEnd) < 0)
        return -1;

    click_chatter("IGMP group member: leave %s", to.unparse().c_str());
    self->push_listen(to, create_igmp_leave_record());
    return 0;
}

void IgmpGroupMember::add_handlers()
{
    add_write_handler("join", &join, (void *)0);
    add_write_handler("leave", &leave, (void *)0);
}

void IgmpGroupMember::push(int port, Packet *packet)
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
        if (is_igmp_membership_query(packet->data()))
        {
            auto data_ptr = packet->data();
            accept_query(IgmpMembershipQuery::read(data_ptr));
        }
    }
}

void IgmpGroupMember::accept_query(const IgmpMembershipQuery &query)
{
    // The spec dictates the following:
    //
    //     When a system receives a Query, it does not respond immediately.
    //     Instead, it delays its response by a random amount of time, bounded
    //     by the Max Resp Time value derived from the Max Resp Code in the
    //     received Query message.
    //
    //     [...]
    //
    //     When a new Query with the Router-Alert option arrives on an
    //     interface, provided the system has state to report, a delay for a
    //     response is randomly selected in the range (0, [Max Resp Time]) where
    //     Max Resp Time is derived from Max Resp Code in the received Query
    //     message. The following rules are then used to determine if a Report
    //     needs to be scheduled and the type of Report to schedule. The rules
    //     are considered in order and only the first matching rule is applied.
    //
    //         1. If there is a pending response to a previous General Query
    //            scheduled sooner than the selected delay, no additional response
    //            needs to be scheduled.
    //
    //         2. If the received Query is a General Query, the interface timer is
    //            used to schedule a response to the General Query after the
    //            selected delay. Any previously pending response to a General
    //            Query is canceled.
    //
    //         3. If the received Query is a Group-Specific Query or a Group-and-
    //            Source-Specific Query and there is no pending response to a
    //            previous Query for this group, then the group timer is used to
    //            schedule a report. If the received Query is a Group-and-Source-
    //            Specific Query, the list of queried sources is recorded to be used
    //            when generating a response.
    //
    //         4. If there already is a pending response to a previous Query
    //            scheduled for this group, and either the new Query is a Group-
    //            Specific Query or the recorded source-list associated with the
    //            group is empty, then the group source-list is cleared and a single
    //            response is scheduled using the group timer. The new response is
    //            scheduled to be sent at the earliest of the remaining time for the
    //            pending report and the selected delay.

    if (!general_response_timer.initialized())
    {
        general_response_timer.initialize(this);
    }

    uint32_t response_delay = click_random(1, query.max_resp_time - 1);
    if (general_response_timer.scheduled() && general_response_timer.remaining_time_csec() <= response_delay)
    {
        // Case #1. Do nothing.
        return;
    }
    else if (query.is_general_query())
    {
        // Case #2. (Re)schedule the response.
        general_response_timer.schedule_after_csec(response_delay);
        return;
    }

    auto response_timer_ptr = group_response_timers.findp(query.group_address);
    if (response_timer_ptr == nullptr)
    {
        IgmpGroupQueryResponse response;
        response.group_address = query.group_address;
        group_response_timers.insert(query.group_address, response);
        response_timer_ptr = group_response_timers.findp(query.group_address);
        assert(response_timer_ptr != nullptr);
        response_timer_ptr->initialize(this);
    }
    if (!response_timer_ptr->scheduled() && response_timer_ptr->remaining_time_csec() <= response_delay)
    {
        // Cases #3 and #4. Schedule a group-specific query, but only if that speeds
        // up our response.
        response_timer_ptr->schedule_after_csec(response_delay);
    }
}

void IgmpGroupMember::IgmpGeneralQueryResponse::operator()() const
{
}

void IgmpGroupMember::IgmpGroupQueryResponse::operator()() const
{
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IgmpGroupMember)

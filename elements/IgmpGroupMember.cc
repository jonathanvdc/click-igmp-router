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
    : state_changed_schedule(this)
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

    // Here's a relevant excerpt from the spec:
    //
    //    An invocation of IPMulticastListen may cause the multicast reception
    //    state of an interface to change, according to the rules in section
    //    3.2.  Each such change affects the per-interface entry for a single
    //    multicast address.
    //
    //    A change of interface state causes the system to immediately transmit
    //    a State-Change Report from that interface.  The type and contents of
    //    the Group Record(s) in that Report are determined by comparing the
    //    filter mode and source list for the affected multicast address before
    //    and after the change, according to the table below.  If no interface
    //    state existed for that multicast address before the change (i.e., the
    //    change consisted of creating a new per-interface record), or if no
    //    state exists after the change (i.e., the change consisted of deleting
    //    a per-interface record), then the "non-existent" state is considered
    //    to have a filter mode of INCLUDE and an empty source list.
    //
    //      Old State         New State         State-Change Record Sent
    //      ---------         ---------         ------------------------
    //
    //      INCLUDE (A)       EXCLUDE (B)       TO_EX (B)
    //
    //      EXCLUDE (A)       INCLUDE (B)       TO_IN (B)
    //
    //
    //    To cover the possibility of the State-Change Report being missed by
    //    one or more multicast routers, it is retransmitted [Robustness
    //    Variable] - 1 more times, at intervals chosen at random from the
    //    range (0, [Unsolicited Report Interval]).

    auto retransmission_count_ptr = state_change_transmission_counts.findp(multicast_address);
    if (retransmission_count_ptr == nullptr)
    {
        state_change_transmission_counts.insert(multicast_address, robustness_variable);
    }
    else
    {
        *retransmission_count_ptr = robustness_variable;
    }

    IgmpTransmitStateChanged event;
    event.elem = this;

    // Transmit a report right away.
    event();

    // Queue [Robustness Variable] - 1 transmissions, at intervals chosen at random from the
    // range (0, [Unsolicited Report Interval]).

    // SPEC INTERPRETATION: 'at intervals' means that we should space the transmissions
    // with spacing chosen randomly from (0, [Unsolicited Report Interval]).

    state_changed_schedule.clear();
    uint32_t delta_csec = 0;
    for (int i = 0; i < robustness_variable - 1; i++)
    {
        delta_csec += click_random(1, unsolicited_report_interval - 1);
        state_changed_schedule.schedule_after_csec(delta_csec, event);
    }
}

IgmpV3MembershipReport IgmpGroupMember::pop_state_changed_report()
{
    // Behold the spec:
    //
    //    If more changes to the same interface state entry occur before all
    //    the retransmissions of the State-Change Report for the first change
    //    have been completed, each such additional change triggers the
    //    immediate transmission of a new State-Change Report.
    //
    //    The contents of the new transmitted report are calculated as follows.
    //    As was done with the first report, the interface state for the
    //    affected group before and after the latest change is compared. The
    //    report records expressing the difference are built according to the
    //    table above. However these records are not transmitted in a message
    //    but instead merged with the contents of the pending report, to create
    //    the new State-Change report. The rules for merging the difference
    //    report resulting from the state change and the pending report are
    //    described below.
    //
    //    The transmission of the merged State-Change Report terminates
    //    retransmissions of the earlier State-Change Reports for the same
    //    multicast address, and becomes the first of [Robustness Variable]
    //    transmissions of State-Change Reports.
    //
    //    Each time a source is included in the difference report calculated
    //    above, retransmission state for that source needs to be maintained
    //    until [Robustness Variable] State-Change reports have been sent by
    //    the host. This is done in order to ensure that a series of
    //    successive state changes do not break the protocol robustness.
    //
    //    If the interface reception-state change that triggers the new report
    //    is a filter-mode change, then the next [Robustness Variable] State-
    //    Change Reports will include a Filter-Mode-Change record.  This
    //    applies even if any number of source-list changes occur in that
    //    period.  The host has to maintain retransmission state for the group
    //    until the [Robustness Variable] State-Change reports have been sent.
    //    When [Robustness Variable] State-Change reports with Filter-Mode-
    //    Change records have been transmitted after the last filter-mode
    //    change, and if source-list changes to the interface reception have
    //    scheduled additional reports, then the next State-Change report will
    //    include Source-List-Change records.
    //
    //    Each time a State-Change Report is transmitted, the contents are
    //    determined as follows. If the report should contain a Filter-Mode-
    //    Change record, then if the current filter-mode of the interface is
    //    INCLUDE, a TO_IN record is included in the report, otherwise a TO_EX
    //    record is included. The
    //    contents of these records are built according to the table below.
    //
    //       Record   Sources included
    //       ------   ----------------
    //       TO_IN    All in the current interface state that must be forwarded
    //       TO_EX    All in the current interface state that must be blocked

    Vector<IPAddress> dead_addresses;
    IgmpV3MembershipReport report;
    for (auto iterator = state_change_transmission_counts.begin(); iterator != state_change_transmission_counts.end(); iterator++)
    {
        auto record_ptr = filter.get_record_or_null(iterator.key());
        IgmpFilterRecord record;
        if (record_ptr == nullptr)
        {
            record.filter_mode = IgmpFilterMode::Include;
        }
        else
        {
            record = *record_ptr;
        }
        report.group_records.push_back(IgmpV3GroupRecord(iterator.key(), record, true));

        auto &val = iterator.value();
        if (--val <= 0)
        {
            dead_addresses.push_back(iterator.key());
        }
    }
    for (const auto &address : dead_addresses)
    {
        state_change_transmission_counts.erase(address);
    }
    return report;
}

void IgmpGroupMember::transmit_membership_report(const IgmpV3MembershipReport &report)
{
    // Well-hidden paragraph from the spec:
    //
    //     If the resulting Current-State Record has an empty set of source
    //     addresses, then no response is sent.
    if (report.group_records.size() == 0)
    {
        return;
    }

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
        IgmpGeneralQueryResponse response;
        response.elem = this;
        general_response_timer = CallbackTimer<IgmpGeneralQueryResponse>(response);
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
        response.elem = this;
        response.group_address = query.group_address;
        group_response_timers.insert(query.group_address, response);
        response_timer_ptr = group_response_timers.findp(query.group_address);
        assert(response_timer_ptr != nullptr);
        response_timer_ptr->initialize(this);
    }
    if (!response_timer_ptr->scheduled() && response_timer_ptr->remaining_time_csec() <= response_delay && query.source_addresses.size() == 0)
    {
        // Cases #3 and #4. Schedule a group-specific query, but only if that speeds
        // up our response.
        response_timer_ptr->schedule_after_csec(response_delay);
    }
}

void IgmpGroupMember::IgmpGeneralQueryResponse::operator()() const
{
    // Here's what the spec says about this.
    //
    //     When the timer in a pending response record expires, the system
    //     transmits, on the associated interface, one or more Report messages
    //     carrying one or more Current-State Records (see section 4.2.12), as
    //     follows:
    //
    //         1. If the expired timer is the interface timer (i.e., it is a pending
    //            response to a General Query), then one Current-State Record is
    //            sent for each multicast address for which the specified interface
    //            has reception state, as described in section 3.2. The Current-
    //            State Record carries the multicast address and its associated
    //            filter mode (MODE_IS_INCLUDE or MODE_IS_EXCLUDE) and source list.
    //            Multiple Current-State Records are packed into individual Report
    //            messages, to the extent possible.
    //
    //            [...]

    // Create a membership report and fill it with group records for all the multicast
    // addresses.
    IgmpV3MembershipReport report;
    for (auto iterator = elem->filter.begin(); iterator != elem->filter.end(); iterator++)
    {
        report.group_records.push_back(IgmpV3GroupRecord(iterator.key(), iterator.value(), false));
    }

    // Transmit the report.
    elem->transmit_membership_report(report);
}

void IgmpGroupMember::IgmpGroupQueryResponse::operator()() const
{
    // According to the spec:
    //
    //         2. If the expired timer is a group timer and the list of recorded
    //            sources for the that group is empty (i.e., it is a pending
    //            response to a Group-Specific Query), then if and only if the
    //            interface has reception state for that group address, a single
    //            Current-State Record is sent for that address. The Current-State
    //            Record carries the multicast address and its associated filter
    //            mode (MODE_IS_INCLUDE or MODE_IS_EXCLUDE) and source list.

    // Create a membership report and give it a group record for a single multicast
    // address.
    IgmpV3MembershipReport report;
    auto record_ptr = elem->filter.get_record_or_null(group_address);
    if (record_ptr == nullptr)
    {
        // Well-hidden paragraph from the spec:
        //
        //     If the resulting Current-State Record has an empty set of source
        //     addresses, then no response is sent.
        //
        // I think this can be interpreted as: "if a group member's state for a multicast address
        // is 'mode-is-include({})'", then don't transmit anything. My reasoning for doing so is
        // that 'mode-is-include({})' really does have an empty set of source addresses.

        return;
    }

    report.group_records.push_back(IgmpV3GroupRecord(group_address, *record_ptr, false));

    // And transmit it.
    elem->transmit_membership_report(report);
}

void IgmpGroupMember::IgmpTransmitStateChanged::operator()() const
{
    elem->transmit_membership_report(elem->pop_state_changed_report());
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IgmpGroupMember)

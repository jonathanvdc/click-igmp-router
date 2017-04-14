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
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IgmpRouter)

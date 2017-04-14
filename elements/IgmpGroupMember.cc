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
    : delayed_responses(this)
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
    IgmpMembershipQueryResponse response;
    response.query = query;
    delayed_responses.schedule_after_csec(click_random(1, query.max_resp_time), response);
}

void IgmpGroupMember::IgmpMembershipQueryResponse::operator()() const
{
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IgmpGroupMember)

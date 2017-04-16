#include "IgmpCheckChecksum.hh"

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include "IgmpMessage.hh"

CLICK_DECLS
IgmpCheckChecksum::IgmpCheckChecksum()
{
}

IgmpCheckChecksum::~IgmpCheckChecksum()
{
}

int IgmpCheckChecksum::configure(Vector<String> &conf, ErrorHandler *errh)
{
    // Nothing to do here.
    if (cp_va_kparse(conf, this, errh, cpEnd) < 0)
        return -1;
    return 0;
}

void IgmpCheckChecksum::push(int port, Packet *packet)
{
    auto checksum = get_igmp_checksum(packet->data());
    auto correct_checksum = compute_igmp_checksum(packet->data(), packet->length());
    if (checksum == correct_checksum)
    {
        output(0).push(packet);
    }
    else
    {
        output(1).push(packet);
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IgmpCheckChecksum)

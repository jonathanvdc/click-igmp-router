#include "IgmpCheckHeader.hh"

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include "IgmpMessage.hh"

CLICK_DECLS
IgmpCheckHeader::IgmpCheckHeader()
{
}

IgmpCheckHeader::~IgmpCheckHeader()
{
}

int IgmpCheckHeader::configure(Vector<String> &conf, ErrorHandler *errh)
{
    // Nothing to do here.
    if (cp_va_kparse(conf, this, errh, cpEnd) < 0)
        return -1;
    return 0;
}

void IgmpCheckHeader::push(int port, Packet *packet)
{
    WritablePacket *result = packet->uniqueify();
    if (get_igmp_checksum(result->data()) == compute_igmp_checksum(result->data(), result->length()))
    {
        output(0).push(result);
    }
    else
    {
        output(1).push(result);
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IgmpCheckHeader)

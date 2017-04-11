#include "IgmpInputHandler.hh"

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include "IgmpMessage.hh"
#include "IgmpFilter.hh"

CLICK_DECLS
IgmpInputHandler::IgmpInputHandler()
{
}

IgmpInputHandler::~IgmpInputHandler()
{
}

int IgmpInputHandler::configure(Vector<String> &conf, ErrorHandler *errh)
{
    // Nothing to do here.
    if (cp_va_kparse(conf, this, errh, cpEnd) < 0)
        return -1;
    return 0;
}

void IgmpInputHandler::push_join(const IPAddress &multicast_address)
{
    click_chatter("sending join request for multicast address %s", multicast_address.unparse().c_str());
}

void IgmpInputHandler::push_leave(const IPAddress &multicast_address)
{
    click_chatter("sending leave request for multicast address %s", multicast_address.unparse().c_str());
}

int IgmpInputHandler::join(const String &conf, Element *e, void *, ErrorHandler *errh)
{
    IgmpInputHandler *self = (IgmpInputHandler *)e;
    IPAddress to;
    if (cp_va_kparse(conf, self, errh, "TO", cpkM, cpIPAddress, &to, cpEnd) < 0)
        return -1;

    self->filter.join(to);
    self->push_join(to);
    return 0;
}

int IgmpInputHandler::leave(const String &conf, Element *e, void *, ErrorHandler *errh)
{
    IgmpInputHandler *self = (IgmpInputHandler *)e;
    IPAddress to;
    if (cp_va_kparse(conf, self, errh, "TO", cpkM, cpIPAddress, &to, cpEnd) < 0)
        return -1;

    self->filter.leave(to);
    self->push_leave(to);
    return 0;
}

void IgmpInputHandler::add_handlers()
{
    add_write_handler("join", &join, (void *)0);
    add_write_handler("leave", &leave, (void *)0);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IgmpInputHandler)

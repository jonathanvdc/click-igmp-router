#pragma once

#include <click/config.h>
#include <click/element.hh>
#include "IgmpRouterFilter.hh"

CLICK_DECLS

class IgmpRouter;

class IgmpRouter : public Element
{
  public:
    IgmpRouter();
    ~IgmpRouter();

    // Description of ports:
    //
    //     Input:
    //         0. Incoming IP packets which are filtered based on their source
    //            address.
    //
    //         1. Incoming IGMP packets.
    //
    //     Output:
    //         0. Generated IGMP packets.
    //
    //         1. Incoming IP packets which have been filtered based on their
    //            source address.
    //
    //         2. Incoming IP packets which were filtered out. They are not intended
    //            for the current host.

    const char *class_name() const { return "IgmpRouter"; }
    const char *port_count() const { return "2/3"; }
    const char *processing() const { return PUSH; }

    int configure(Vector<String> &, ErrorHandler *);

    void push(int port, Packet *packet);

  private:
    IgmpRouterFilter filter;
};

CLICK_ENDDECLS
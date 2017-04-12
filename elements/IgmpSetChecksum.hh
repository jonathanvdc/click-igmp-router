#pragma once

#include <click/config.h>
#include <click/element.hh>
#include "IgmpFilter.hh"

CLICK_DECLS

class IgmpSetChecksum;

class IgmpSetChecksum : public Element
{
  public:
    IgmpSetChecksum();
    ~IgmpSetChecksum();

    // Description of ports:
    //
    //     Input:
    //         0. IGMP packets.
    //
    //     Output:
    //         0. IGMP packets with correct checksums.

    const char *class_name() const { return "IgmpSetChecksum"; }
    const char *port_count() const { return "1/1"; }
    const char *processing() const { return PUSH; }

    int configure(Vector<String> &, ErrorHandler *);

    void push(int port, Packet *packet);
};

CLICK_ENDDECLS
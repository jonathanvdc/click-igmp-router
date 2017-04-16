#pragma once

#include <click/config.h>
#include <click/element.hh>

CLICK_DECLS

class IgmpCheckChecksum;

class IgmpCheckChecksum : public Element
{
  public:
    IgmpCheckChecksum();
    ~IgmpCheckChecksum();

    // Description of ports:
    //
    //     Input:
    //         0. IGMP packets.
    //
    //     Output:
    //         0. IGMP packets with correct checksums.
    //         1. IGMP packets with incorrect checksums.

    const char *class_name() const { return "IgmpCheckChecksum"; }
    const char *port_count() const { return "1/2"; }
    const char *processing() const { return PUSH; }

    int configure(Vector<String> &, ErrorHandler *);

    void push(int port, Packet *packet);
};

CLICK_ENDDECLS
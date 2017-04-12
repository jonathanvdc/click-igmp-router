#pragma once

#include <click/config.h>
#include <click/element.hh>

CLICK_DECLS

class IgmpCheckHeader;

class IgmpCheckHeader : public Element
{
  public:
    IgmpCheckHeader();
    ~IgmpCheckHeader();

    // Description of ports:
    //
    //     Input:
    //         0. IGMP packets.
    //
    //     Output:
    //         0. IGMP packets with valid checksums.
    //         1. IGMP packets with invalid checksums.

    const char *class_name() const { return "IgmpCheckHeader"; }
    const char *port_count() const { return "1/2"; }
    const char *processing() const { return PUSH; }

    int configure(Vector<String> &, ErrorHandler *);

    void push(int port, Packet *packet);
};

CLICK_ENDDECLS
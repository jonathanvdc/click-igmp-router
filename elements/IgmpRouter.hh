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
  //         2. Incoming IP packets which were filtered out. The router does
  //            not believe that these are multicast packets intended for a
  //            client on the network.

  const char *class_name() const { return "IgmpRouter"; }
  const char *port_count() const { return "2/3"; }
  const char *processing() const { return PUSH; }

  int configure(Vector<String> &, ErrorHandler *);

  void push(int port, Packet *packet);

private:
  void handle_igmp_packet(Packet *packet);
  void query_multicast_group(const IPAddress &multicast_address);

  IgmpRouterFilter filter;
};

CLICK_ENDDECLS
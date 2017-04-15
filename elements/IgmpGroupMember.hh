#pragma once

#include <click/config.h>
#include <click/element.hh>
#include <click/hashmap.hh>
#include "CallbackTimer.hh"
#include "EventSchedule.hh"
#include "IgmpMessageManip.hh"
#include "IgmpMemberFilter.hh"

CLICK_DECLS

class IgmpGroupMember;

class IgmpGroupMember : public Element
{
public:
  IgmpGroupMember();
  ~IgmpGroupMember();

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

  const char *class_name() const { return "IgmpGroupMember"; }
  const char *port_count() const { return "2/3"; }
  const char *processing() const { return PUSH; }

  int configure(Vector<String> &, ErrorHandler *);

  static int join(const String &conf, Element *e, void *thunk, ErrorHandler *errh);
  static int leave(const String &conf, Element *e, void *thunk, ErrorHandler *errh);
  static int config(const String &conf, Element *e, void *thunk, ErrorHandler *errh);

  void add_handlers();

  void push(int port, Packet *packet);

private:
  /// A timer callback that responds to IGMP general queries.
  struct IgmpGeneralQueryResponse
  {
    IgmpGroupMember *elem;

    void operator()() const;
  };

  /// A timer callback that responds to IGMP group-specific queries.
  struct IgmpGroupQueryResponse
  {
    IgmpGroupMember *elem;
    IPAddress group_address;

    void operator()() const;
  };

  /// A timer callback that transmits state-changed records.
  struct IgmpTransmitStateChanged
  {
    IgmpGroupMember *elem;

    void operator()() const;
  };

  void push_listen(const IPAddress &multicast_address, const IgmpFilterRecord &record);
  void accept_query(const IgmpMembershipQuery &query);
  void transmit_membership_report(const IgmpV3MembershipReport &report);

  /// Creates a state-changed report.
  IgmpV3MembershipReport pop_state_changed_report();

  /// The robustness variable for this group member. This field's
  /// default value is 2.
  uint8_t robustness_variable = 2;

  // The Unsolicited Report Interval is the time between repetitions of a
  // host’s initial report of membership in a group. Default: 1 second.
  uint32_t unsolicited_report_interval = 10;

  /// The filter for this IGMP group member.
  IgmpMemberFilter filter;

  /// A schedule of state-changed transmissions.
  EventSchedule<IgmpTransmitStateChanged> state_changed_schedule;
  /// A map from IP multicast addresses to the number of times they should
  /// be included in a state-changed report.
  HashMap<IPAddress, int> state_change_transmission_counts;

  CallbackTimer<IgmpGeneralQueryResponse> general_response_timer;
  HashMap<IPAddress, CallbackTimer<IgmpGroupQueryResponse>> group_response_timers;
};

CLICK_ENDDECLS
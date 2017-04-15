#pragma once

#include <click/config.h>
#include <click/element.hh>
#include "CallbackTimer.hh"
#include "EventSchedule.hh"
#include "IgmpMessageManip.hh"
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
    /// A timer callback that sends periodic general queries.
    struct SendPeriodicGeneralQuery
    {
        SendPeriodicGeneralQuery()
            : elem(nullptr)
        {
        }
        SendPeriodicGeneralQuery(IgmpRouter *elem)
            : elem(elem)
        {
        }
        IgmpRouter *elem;

        void operator()() const;
    };

    /// A timer callback that sends a group-specific query.
    struct SendGroupSpecificQuery
    {
        SendGroupSpecificQuery()
            : elem(nullptr), group_address()
        {
        }
        SendGroupSpecificQuery(IgmpRouter *elem, const IPAddress &group_address)
            : elem(elem), group_address(group_address)
        {
        }
        IgmpRouter *elem;
        IPAddress group_address;

        void operator()() const;
    };

    /// A timer callback for the other querier present timer.
    struct OtherQuerierGone
    {
        OtherQuerierGone()
            : elem(nullptr)
        {
        }
        OtherQuerierGone(IgmpRouter *elem)
            : elem(elem)
        {
        }
        IgmpRouter *elem;

        void operator()() const;
    };

    void handle_igmp_packet(Packet *packet);
    void handle_igmp_membership_query(const IgmpMembershipQuery &query, const IPAddress &source_address);
    void transmit_membership_query(const IgmpMembershipQuery &query);
    void init_startup_queries();

    IPAddress address;
    IgmpRouterFilter filter;
    EventSchedule<SendGroupSpecificQuery> query_schedule;
    CallbackTimer<SendPeriodicGeneralQuery> general_query_timer;
    unsigned int startup_general_queries_remaining;
    bool other_querier_present = false;
    CallbackTimer<OtherQuerierGone> other_querier_present_timer;
};

CLICK_ENDDECLS
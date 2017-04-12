#pragma once

#include <click/config.h>
#include <click/element.hh>
#include <click/hashmap.hh>
#include <click/vector.hh>
#include <clicknet/ip.h>
#include "IgmpMessage.hh"
#include "IgmpMemberFilter.hh"

CLICK_DECLS

/// A value with an associated timer.
template <typename T>
struct Timed
{
    Timed(const T &value, Element *owner, TimerCallback timer_callback, void *timer_data)
        : timer(timer_callback, timer_data), value(value)
    {
        timer.initialize(owner);
    }

    /// The value that is timed.
    T value;

  private:
    /// The timer associated with the value.
    Timer timer;
};

/// A record in an IGMP router filter.
struct IgmpRouterFilterRecord
{
    /// The filter record's mode.
    IgmpFilterMode filter_mode;

    /// The filter record's list of source addresses and their timers.
    Vector<Timed<IPAddress>> source_records;
};

/// A router "filter" for IGMP packets. It decides which addresses are listened to and which are not.
class IgmpRouterFilter
{
  public:
    IgmpRouterFilter(Element *owner)
        : owner(owner)
    {
    }

    unsigned int get_robustness_variable() const { return robustness_variable; }
    unsigned int &get_robustness_variable() { return robustness_variable; }

    /// Tests if the IGMP filter is listening to the given source address for the given multicast
    /// address.
    bool is_listening_to(const IPAddress &multicast_address, const IPAddress &source_address) const
    {
        if (multicast_address == all_systems_multicast_address)
        {
            // According to the spec:
            //
            // The all-systems multicast address, 224.0.0.1, is handled as a special
            // case. On all systems -- that is all hosts and routers, including
            // multicast routers -- reception of packets destined to the all-systems
            // multicast address, from all sources, is permanently enabled on all
            // interfaces on which multicast reception is supported. No IGMP
            // messages are ever sent regarding the all-systems multicast address.
            return true;
        }
        else if (multicast_address == report_multicast_address)
        {
            // According to the spec:
            //
            // On each interface over which this protocol is being run, the router MUST
            // enable reception of multicast address 224.0.0.22, from all sources (and MUST
            // perform the group member part of IGMPv3 for that address on that interface).
            return true;
        }

        Timed<IgmpRouterFilterRecord> *record_ptr = records.findp(multicast_address);
        if (record_ptr == nullptr)
        {
            return false;
        }

        bool is_excluding = record_ptr->value->filter_mode == IgmpFilterMode::Exclude;
        for (const auto &item : record_ptr->value->source_addresses)
        {
            if (item == source_address)
            {
                return !is_excluding;
            }
        }
        return is_excluding;
    }

  private:
    unsigned int robustness_variable = default_robustness_variable;
    Element *owner;
    HashMap<IPAddress, Timed<IgmpRouterFilterRecord>> records;
};

CLICK_ENDDECLS
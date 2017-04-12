#pragma once

#include <click/config.h>
#include <click/element.hh>
#include <click/hashmap.hh>
#include <click/vector.hh>
#include <click/timer.hh>
#include <clicknet/ip.h>
#include "IgmpMessage.hh"
#include "IgmpMemberFilter.hh"
#include "IgmpRouterVariables.hh"

CLICK_DECLS

/// A value with an associated timer.
template <typename T>
struct Timed
{
    Timed()
        : value(), timer()
    {
    }

    Timed(const T &value, TimerCallback timer_callback, void *timer_data)
        : value(value), timer(timer_callback, timer_data)
    {
    }

    /// The value that is timed.
    T value;

    /// Initializes this timed value's timer by assigning it to an owner.
    void initialize(Element *owner)
    {
        timer.initialize(owner);
    }

  private:
    /// The timer associated with the value.
    Timer timer;
};

/// A record in an IGMP router filter.
struct IgmpRouterFilterRecord
{
    // The spec on this data structure:
    //
    // When a router filter-mode for a group is EXCLUDE, the source record
    // list contains two types of sources. The first type is the set which
    // represents conflicts in the desired reception state; this set must be
    // forwarded by some router on the network. The second type is the set
    // of sources which hosts have requested to not be forwarded. [...]
    //
    // When a router filter-mode for a group is INCLUDE, the source record
    // list is the list of sources desired for the group. This is the total
    // desired set of sources for that group. Each source in the source
    // record list must be forwarded by some router on the network.

    /// The filter record's mode.
    IgmpFilterMode filter_mode;

    /// The filter record's list of source addresses and their timers.
    Vector<Timed<IPAddress>> source_records;

    /// The filter record's list of excluded addresses.
    /// This list must be empty if the filter mode is INCLUDE.
    Vector<IPAddress> excluded_records;
};

/// A router "filter" for IGMP packets. It decides which addresses are listened to and which are not.
class IgmpRouterFilter
{
  public:
    IgmpRouterFilter(Element *owner)
        : owner(owner)
    {
    }

    const IgmpRouterVariables &get_router_variables() const { return vars; }
    IgmpRouterVariables &get_router_variables() { return vars; }

    /// Gets a pointer to the record for the given multicast address.
    Timed<IgmpRouterFilterRecord> *get_record(const IPAddress &multicast_address)
    {
        return records.findp(multicast_address);
    }

    /// Gets a pointer to the record for the given multicast address.
    const Timed<IgmpRouterFilterRecord> *get_record(const IPAddress &multicast_address) const
    {
        return records.findp(multicast_address);
    }

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

        const Timed<IgmpRouterFilterRecord> *record_ptr = get_record(multicast_address);
        if (record_ptr == nullptr)
        {
            return false;
        }

        bool is_excluding = record_ptr->value.filter_mode == IgmpFilterMode::Exclude;
        for (const auto &item : record_ptr->value.source_records)
        {
            if (item.value == source_address)
            {
                return !is_excluding;
            }
        }
        return is_excluding;
    }

  private:
    Element *owner;
    IgmpRouterVariables vars;
    HashMap<IPAddress, Timed<IgmpRouterFilterRecord>> records;
};

CLICK_ENDDECLS
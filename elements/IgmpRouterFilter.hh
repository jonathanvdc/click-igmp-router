#pragma once

#include <click/config.h>
#include <click/element.hh>
#include <click/hashmap.hh>
#include <click/vector.hh>
#include <click/timer.hh>
#include <clicknet/ip.h>
#include "CallbackTimer.hh"
#include "IgmpMessage.hh"
#include "IgmpMemberFilter.hh"
#include "IgmpRouterVariables.hh"

CLICK_DECLS

class IgmpRouterFilter;

/// A callback for source record timers.
class IgmpRouterSourceRecordCallback final
{
  public:
    IgmpRouterSourceRecordCallback(const IPAddress &multicast_address, const IPAddress &source_address, IgmpRouterFilter *filter)
        : multicast_address(multicast_address), source_address(source_address), filter(filter)
    {
    }

    void operator()() const;

  private:
    IPAddress multicast_address;
    IPAddress source_address;
    IgmpRouterFilter *filter;
};

/// Represents an IGMP source record in a router group record.
class IgmpRouterSourceRecord final
{
  public:
    IgmpRouterSourceRecord(const IPAddress &multicast_address, const IPAddress &source_address, IgmpRouterFilter *filter)
        : source_address(source_address), timer(multicast_address, source_address, filter)
    {
    }

    IPAddress get_source_address() const { return source_address; }

    void initialize(Element *owner)
    {
        timer.initialize(owner);
    }

    void schedule_after_sec(uint32_t delta_sec)
    {
        timer.schedule_after_sec(delta_sec);
    }

    void schedule_after_msec(uint32_t delta_msec)
    {
        timer.schedule_after_msec(delta_msec);
    }

    void schedule_after_csec(uint32_t delta_csec)
    {
        schedule_after_msec(delta_csec * 100);
    }

  private:
    IPAddress source_address;
    CallbackTimer<IgmpRouterSourceRecordCallback> timer;
};

/// A callback that converts group records in exclude mode to group records
/// in include mode.
class IgmpRouterGroupRecordCallback final
{
  public:
    IgmpRouterGroupRecordCallback()
        : multicast_address(), filter(nullptr)
    {
    }

    IgmpRouterGroupRecordCallback(const IPAddress &multicast_address, IgmpRouterFilter *filter)
        : multicast_address(multicast_address), filter(filter)
    {
    }

    void operator()() const;

  private:
    IPAddress multicast_address;
    IgmpRouterFilter *filter;
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

    /// The filter record's timer.
    CallbackTimer<IgmpRouterGroupRecordCallback> timer;

    /// The filter record's list of source addresses and their timers.
    Vector<IgmpRouterSourceRecord> source_records;

    /// The filter record's list of excluded addresses.
    /// This list must be empty if the filter mode is INCLUDE.
    Vector<IPAddress> excluded_addresses;

    /// Gets a list of all source addresses.
    Vector<IPAddress> get_source_addresses() const
    {
        Vector<IPAddress> results;
        for (const auto &item : source_records)
        {
            results.push_back(item.get_source_address());
        }
        return results;
    }

    /// Erases all source records which match the given predicate. A Boolean
    /// result tells if any source records were actually erased.
    template <typename TPredicate>
    bool erase_source_records(const TPredicate &predicate)
    {
        bool erased_any = false;
        size_t i = 0;
        while (i < source_records.size())
        {
            if (predicate(source_records[i]))
            {
                source_records.erase(source_records.begin() + i);
                erased_any = true;
            }
            else
            {
                i++;
            }
        }
        return erased_any;
    }
};

/// A router "filter" for IGMP packets. It decides which addresses are listened to and which are not.
class IgmpRouterFilter
{
  public:
    IgmpRouterFilter(Element *owner, bool enable_timers)
        : owner(owner), enable_timers(enable_timers)
    {
    }

    const IgmpRouterVariables &get_router_variables() const { return vars; }
    IgmpRouterVariables &get_router_variables() { return vars; }

    /// Gets a pointer to the record for the given multicast address.
    IgmpRouterFilterRecord *get_record(const IPAddress &multicast_address)
    {
        return records.findp(multicast_address);
    }

    /// Gets a pointer to the record for the given multicast address.
    const IgmpRouterFilterRecord *get_record(const IPAddress &multicast_address) const
    {
        return records.findp(multicast_address);
    }

    /// Gets or creates a source record in the given group record.
    IgmpRouterSourceRecord &get_or_create_source_record(
        IgmpRouterFilterRecord &group_record,
        const IPAddress &multicast_address,
        const IPAddress &source_address)
    {
        for (auto &record : group_record.source_records)
        {
            if (record.get_source_address() == source_address)
            {
                return record;
            }
        }

        group_record.source_records.push_back(
            IgmpRouterSourceRecord(multicast_address, source_address, this));
        auto &record = group_record.source_records[group_record.source_records.size() - 1];
        if (enable_timers)
        {
            record.initialize(owner);
        }
        return record;
    }

    /// Creates a new record for the given multicast address, assigns the given filter
    /// mode to the newly-created record and returns it.
    IgmpRouterFilterRecord *create_record(const IPAddress &multicast_address, IgmpFilterMode filter_mode)
    {
        assert(get_record(multicast_address) == nullptr);
        records.insert(multicast_address, IgmpRouterFilterRecord());
        auto record_ptr = records.findp(multicast_address);
        record_ptr->filter_mode = filter_mode;
        if (filter_mode == IgmpFilterMode::Exclude && enable_timers)
        {
            record_ptr->timer = CallbackTimer<IgmpRouterGroupRecordCallback>(multicast_address, this);
            record_ptr->timer.initialize(owner);
        }
        return record_ptr;
    }

    /// Receives a record that describes a multicast address' current state.
    void receive_current_state_record(const IPAddress &multicast_address, const IgmpFilterRecord &current_state_record);

    /// Tests if the IGMP filter is listening to the given source address for the given multicast
    /// address.
    bool is_listening_to(const IPAddress &multicast_address, const IPAddress &source_address) const;

  private:
    Element *owner;
    IgmpRouterVariables vars;
    bool enable_timers;
    HashMap<IPAddress, IgmpRouterFilterRecord> records;
};

inline void IgmpRouterSourceRecordCallback::operator()() const
{
    auto record_ptr = filter->get_record(multicast_address);
    if (record_ptr == nullptr)
    {
        return;
    }

    bool erased_any = record_ptr->erase_source_records(
        [=](const IgmpRouterSourceRecord &source_record) {
            return source_record.get_source_address() == source_address;
        });

    if (erased_any && record_ptr->filter_mode == IgmpFilterMode::Exclude)
    {
        record_ptr->excluded_addresses.push_back(source_address);
    }
}

inline void IgmpRouterGroupRecordCallback::operator()() const
{
    if (filter == nullptr)
    {
        return;
    }

    auto record_ptr = filter->get_record(multicast_address);
    if (record_ptr == nullptr)
    {
        return;
    }

    if (record_ptr->filter_mode == IgmpFilterMode::Exclude)
    {
        record_ptr->filter_mode = IgmpFilterMode::Include;
        record_ptr->excluded_addresses.clear();
    }
}

inline void IgmpRouterFilter::receive_current_state_record(
    const IPAddress &multicast_address, const IgmpFilterRecord &current_state_record)
{
    // When receiving Current-State Records, a router updates both its group
    // and source timers. In some circumstances, the reception of a type of
    // group record will cause the router filter-mode for that group to
    // change. The table below describes the actions, with respect to state
    // and timers that occur to a router’s state upon reception of Current-
    // State Records.
    //
    // The following notation is used to describe the updating of source
    // timers. The notation ( A, B ) will be used to represent the total
    // number of sources for a particular group, where
    //
    //     A = set of source records whose source timers > 0 (Sources that at
    //         least one host has requested to be forwarded)
    //     B = set of source records whose source timers = 0 (Sources that IGMP
    //         will suggest to the routing protocol not to forward)
    //
    // Note that there will only be two sets when a router’s filter-mode for
    // a group is EXCLUDE. When a router’s filter-mode for a group is
    // INCLUDE, a single set is used to describe the set of sources
    // requested to be forwarded (e.g., simply (A)).
    //
    // In the following tables, abbreviations are used for several variables
    // (all of which are described in detail in section 8). The variable
    // GMI is an abbreviation for the Group Membership Interval, which is
    // the time in which group memberships will time out. The variable LMQT
    // is an abbreviation for the Last Member Query Time, which is the total
    // time spent after Last Member Query Count retransmissions. LMQT
    // represents the "leave latency", or the difference between the
    // transmission of a membership change and the change in the information
    // given to the routing protocol.
    //
    // Within the "Actions" section of the router state tables, we use the
    // notation ’A=J’, which means that the set A of source records should
    // have their source timers set to value J. ’Delete A’ means that the
    // set A of source records should be deleted. ’Group Timer=J’ means
    // that the Group Timer for the group should be set to value J.
    //
    //    Router State   Report Rec'd  New Router State         Actions
    //    ------------   ------------  ----------------         -------
    //
    //    INCLUDE (A)    IS_IN (B)     INCLUDE (A+B)            (B)=GMI
    //
    //    INCLUDE (A)    IS_EX (B)     EXCLUDE (A*B,B-A)        (B-A)=0
    //                                                          Delete (A-B)
    //                                                          Group Timer=GMI
    //
    //    EXCLUDE (X,Y)  IS_IN (A)     EXCLUDE (X+A,Y-A)        (A)=GMI
    //
    //    EXCLUDE (X,Y)  IS_EX (A)     EXCLUDE (A-Y,Y*A)        (A-X-Y)=GMI
    //                                                          Delete (X-A)
    //                                                          Delete (Y-A)
    //                                                          Group Timer=GMI

    auto record_ptr = get_record(multicast_address);
    if (record_ptr == nullptr)
    {
        record_ptr = create_record(multicast_address, IgmpFilterMode::Include);
    }

    if (record_ptr->filter_mode == IgmpFilterMode::Include)
    {
        if (current_state_record.filter_mode == IgmpFilterMode::Include)
        {
            //    Router State   Report Rec'd  New Router State         Actions
            //    ------------   ------------  ----------------         -------
            //
            //    INCLUDE (A)    IS_IN (B)     INCLUDE (A+B)            (B)=GMI

            for (const auto &source_address : current_state_record.source_addresses)
            {
                auto &record = get_or_create_source_record(*record_ptr, multicast_address, source_address);
                record.schedule_after_csec(get_router_variables().get_group_membership_interval());
            }
        }
        else
        {
            //    Router State   Report Rec'd  New Router State         Actions
            //    ------------   ------------  ----------------         -------
            //
            //    INCLUDE (A)    IS_EX (B)     EXCLUDE (A*B,B-A)        (B-A)=0
            //                                                          Delete (A-B)
            //                                                          Group Timer=GMI

            // Update the filter mode.
            record_ptr->filter_mode = IgmpFilterMode::Exclude;

            // Set excluded addresses to B-A.
            record_ptr->excluded_addresses = difference_vectors(
                current_state_record.source_addresses, record_ptr->get_source_addresses());

            // Set source records to A*B by deleting all elements of A which are not in B.
            record_ptr->erase_source_records([&current_state_record](const IgmpRouterSourceRecord &source_record) {
                return !in_vector(
                    source_record.get_source_address(),
                    current_state_record.source_addresses);
            });

            // Set the group timer to the GMI.
            record_ptr->timer.schedule_after_csec(get_router_variables().get_group_membership_interval());
        }
    }
    else
    {
        if (current_state_record.filter_mode == IgmpFilterMode::Include)
        {
            //    Router State   Report Rec'd  New Router State         Actions
            //    ------------   ------------  ----------------         -------
            //
            //    EXCLUDE (X,Y)  IS_IN (A)     EXCLUDE (X+A,Y-A)        (A)=GMI

            record_ptr->excluded_addresses = difference_vectors(
                record_ptr->excluded_addresses, current_state_record.source_addresses);

            for (const auto &source_address : current_state_record.source_addresses)
            {
                auto &record = get_or_create_source_record(*record_ptr, multicast_address, source_address);
                record.schedule_after_csec(get_router_variables().get_group_membership_interval());
            }
        }
        else
        {
            //    Router State   Report Rec'd  New Router State         Actions
            //    ------------   ------------  ----------------         -------
            //
            //    EXCLUDE (X,Y)  IS_EX (A)     EXCLUDE (A-Y,Y*A)        (A-X-Y)=GMI
            //                                                          Delete (X-A)
            //                                                          Delete (Y-A)
            //                                                          Group Timer=GMI

            auto prev_source_addresses = record_ptr->get_source_addresses();

            // Delete X-A from the source records by erasing all source records that are not
            // in A. This nets us X-(X-A) = X*A.
            record_ptr->erase_source_records([&current_state_record](const IgmpRouterSourceRecord &source_record) {
                return !in_vector(
                    source_record.get_source_address(),
                    current_state_record.source_addresses);
            });

            // Now delete X*Y from the source records by erasing all source records that are
            // in Y. This nets us X*A-(X*Y) = X*A - Y.
            record_ptr->erase_source_records([record_ptr](const IgmpRouterSourceRecord &source_record) {
                return in_vector(
                    source_record.get_source_address(),
                    record_ptr->excluded_addresses);
            });

            // Add A-X-Y to the source records and set their timers to the GMI.
            for (const auto &source_address : difference_vectors(
                     difference_vectors(current_state_record.source_addresses, prev_source_addresses),
                     record_ptr->excluded_addresses))
            {
                auto &record = get_or_create_source_record(*record_ptr, multicast_address, source_address);
                record.schedule_after_csec(get_router_variables().get_group_membership_interval());
            }

            // Update the list of excluded addresses.
            record_ptr->excluded_addresses = intersect_vectors(
                record_ptr->excluded_addresses, current_state_record.source_addresses);

            // Set the group timer to the GMI.
            record_ptr->timer.schedule_after_csec(get_router_variables().get_group_membership_interval());
        }
    }
}

inline bool IgmpRouterFilter::is_listening_to(const IPAddress &multicast_address, const IPAddress &source_address) const
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

    const IgmpRouterFilterRecord *record_ptr = get_record(multicast_address);
    if (record_ptr == nullptr)
    {
        return false;
    }

    if (record_ptr->filter_mode == IgmpFilterMode::Exclude)
    {
        return !in_vector(source_address, record_ptr->excluded_addresses);
    }
    else
    {
        for (const auto &item : record_ptr->source_records)
        {
            if (item.get_source_address() == source_address)
            {
                return true;
            }
        }
        return false;
    }
}

CLICK_ENDDECLS
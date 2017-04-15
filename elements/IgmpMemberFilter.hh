#pragma once

#include <click/config.h>
#include <click/hashmap.hh>
#include <click/vector.hh>
#include <clicknet/ip.h>
#include "IgmpMessage.hh"

CLICK_DECLS

/// An enumeration of possible interpretations of entries in the source addresses
/// field of an IGMP filter record.
enum class IgmpFilterMode
{
    /// In INCLUDE mode, reception of packets sent to the specified multicast address
    /// is requested *only* from those IP source addresses listed in the source-list
    /// parameter.
    Include,

    /// In EXCLUDE mode, reception of packets sent to the given multicast address is
    /// requested from all IP source addresses *except* those listed in the source-list
    /// parameter.
    Exclude
};

/// A record in an IGMP filter.
struct IgmpFilterRecord
{
    /// The filter record's mode.
    IgmpFilterMode filter_mode;

    /// The filter record's list of source addresses.
    Vector<IPAddress> source_addresses;
};

/// Creates an IGMP filter record that performs a simple 'join:' it listens to all
/// messages from a multicast group, without filtering on specific source addresses.
inline IgmpFilterRecord create_igmp_join_record()
{
    return {IgmpFilterMode::Exclude, Vector<IPAddress>()};
}

/// Creates an IGMP filter record that performs a simple 'leave:' it stops listening to
/// messages from a multicast group, regardless of source addresses.
inline IgmpFilterRecord create_igmp_leave_record()
{
    return {IgmpFilterMode::Include, Vector<IPAddress>()};
}

/// Checks if the specified value is equal to any element of the given vector.
template <typename T>
bool in_vector(const T &value, const Vector<T> &vector)
{
    for (const auto &item : vector)
    {
        if (item == value)
        {
            return true;
        }
    }
    return false;
}

/// Creates a vector whose elements are the intersection of the given
/// vectors.
template <typename T>
Vector<T> intersect_vectors(const Vector<T> &left, const Vector<T> &right)
{
    Vector<T> results;
    for (const auto &item : left)
    {
        if (in_vector<T>(item, right))
        {
            results.push_back(item);
        }
    }
    return results;
}

/// Creates a vector whose elements are the union of the given
/// vectors.
template <typename T>
Vector<T> union_vectors(const Vector<T> &left, const Vector<T> &right)
{
    Vector<T> results = left;
    for (const auto &item : right)
    {
        if (!in_vector<T>(item, results))
        {
            results.push_back(item);
        }
    }
    return results;
}

/// Creates a vector whose elements are the difference of the given
/// vectors.
template <typename T>
Vector<T> difference_vectors(const Vector<T> &left, const Vector<T> &right)
{
    Vector<T> results;
    for (const auto &item : left)
    {
        if (!in_vector<T>(item, right))
        {
            results.push_back(item);
        }
    }
    return results;
}

/// Tests if the lhs vector is a subset of the rhs vector.
template <typename T>
bool is_subset_vectors(const Vector<T> &subset, const Vector<T> &superset)
{
    for (const auto& item : subset)
    {
        if (!in_vector<T>(item, superset))
        {
            return false;
        }
    }
    return true;
}

/// Tests if the given vectors contain the same elements.
template <typename T>
bool set_equality_vectors(const Vector<T> &left, const Vector<T> &right)
{
    return is_subset_vectors(left, right) && is_subset_vectors(right, left);
}

/// A "filter" for IGMP packets. It decides which addresses are listened to and which are not.
class IgmpMemberFilter
{
  public:
    /// Returns a pointer to the record for the given multicast address, or null if it is not found.
    const IgmpFilterRecord *get_record_or_null(const IPAddress &multicast_address) const
    {
        return records.findp(multicast_address);
    }

    typedef typename HashMap<IPAddress, IgmpFilterRecord>::const_iterator iterator;
    typedef typename HashMap<IPAddress, IgmpFilterRecord>::const_iterator const_iterator;

    /// Gets a constant iterator to the start of this filter's records.
    const_iterator begin() const
    {
        return records.begin();
    }

    /// Gets a constant iterator to the end of this filter's records.
    const_iterator end() const
    {
        return records.end();
    }

    /// Listens to the given multicast address. A list of source addresses are either explicitly included
    /// or excluded. A Boolean result tells if the filter's state has changed.
    bool listen(const IPAddress &multicast_address, IgmpFilterMode filter_mode, const Vector<IPAddress> &source_addresses)
    {
        // According to the spec:
        //
        // The socket state evolves in response to each invocation of
        // IPMulticastListen on the socket, as follows:
        //
        //     o If the requested filter mode is INCLUDE *and* the requested source
        //       list is empty, then the entry corresponding to the requested
        //       interface and multicast address is deleted if present. If no such
        //       entry is present, the request is ignored.
        //
        //     o If the requested filter mode is EXCLUDE *or* the requested source
        //       list is non-empty, then the entry corresponding to the requested
        //       interface and multicast address, if present, is changed to contain
        //       the requested filter mode and source list. If no such entry is
        //       present, a new entry is created, using the parameters specified in
        //       the request.

        if (filter_mode == IgmpFilterMode::Include && source_addresses.size() == 0)
        {
            if (records.findp(multicast_address) == nullptr)
            {
                return false;
            }
            else
            {
                records.erase(multicast_address);
                return true;
            }
        }

        bool has_changed = false;
        IgmpFilterRecord *record_ptr = records.findp(multicast_address);
        if (record_ptr == nullptr)
        {
            records.insert(multicast_address, IgmpFilterRecord());
            record_ptr = records.findp(multicast_address);
            has_changed = true;
        }
        if (record_ptr->filter_mode != filter_mode)
        {
            record_ptr->filter_mode = filter_mode;
            has_changed = true;
        }
        
        if (!set_equality_vectors(record_ptr->source_addresses, source_addresses))
        {
            record_ptr->source_addresses = source_addresses;
            has_changed = true;
        }

        return has_changed;
    }

    /// Listens to the given multicast address. A filter record specifies a list of source addresses that
    /// are either explicitly included or excluded. A Boolean result tells if the filter's state has changed.
    bool listen(const IPAddress &multicast_address, const IgmpFilterRecord &record)
    {
        return listen(multicast_address, record.filter_mode, record.source_addresses);
    }

    /// Joins the multicast group with the given multicast address.
    /// A Boolean result tells if the filter's state has changed.
    bool join(const IPAddress &multicast_address)
    {
        return listen(multicast_address, IgmpFilterMode::Exclude, Vector<IPAddress>());
    }

    /// Leaves the multicast group with the given multicast address.
    /// A Boolean result tells if the filter's state has changed.
    bool leave(const IPAddress &multicast_address)
    {
        return listen(multicast_address, IgmpFilterMode::Include, Vector<IPAddress>());
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

        IgmpFilterRecord *record_ptr = records.findp(multicast_address);
        if (record_ptr == nullptr)
        {
            return false;
        }

        bool is_excluding = record_ptr->filter_mode == IgmpFilterMode::Exclude;
        return is_excluding != in_vector(source_address, record_ptr->source_addresses);
    }

  private:
    HashMap<IPAddress, IgmpFilterRecord> records;
};

CLICK_ENDDECLS
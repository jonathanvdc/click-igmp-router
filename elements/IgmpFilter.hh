#ifndef IGMP_FILTER
#define IGMP_FILTER

#include <click/config.h>
#include <click/hashmap.hh>
#include <click/vector.hh>
#include <clicknet/ip.h>

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

/// A "filter" for IGMP packets. It decides which addresses are listened to and which are not.
class IgmpFilter
{
  public:
    /// Listens to the given multicast address. A list of source addresses are either explicitly included
    /// or excluded.
    void listen(const IPAddress &multicast_address, IgmpFilterMode filter_mode, const Vector<IPAddress> &source_addresses)
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
            records.erase(multicast_address);
            return;
        }

        IgmpFilterRecord *record_ptr;
        if (!records.findp(multicast_address))
        {
            records.insert(multicast_address, IgmpFilterRecord());
            record_ptr = records.findp(multicast_address);
        }
        record_ptr->filter_mode = filter_mode;
        record_ptr->source_addresses = source_addresses;
    }

    /// Listens to the given multicast address. A filter record specifies a list of source addresses that
    /// are either explicitly included or excluded.
    void listen(const IPAddress &multicast_address, const IgmpFilterRecord &record)
    {
        listen(multicast_address, record.filter_mode, record.source_addresses);
    }

    /// Joins the multicast group with the given multicast address.
    void join(const IPAddress &multicast_address)
    {
        listen(multicast_address, IgmpFilterMode::Exclude, Vector<IPAddress>());
    }

    /// Leaves the multicast group with the given multicast address.
    void leave(const IPAddress &multicast_address)
    {
        listen(multicast_address, IgmpFilterMode::Include, Vector<IPAddress>());
    }

    /// Tests if the IGMP filter is listening to the given source address for the given multicast
    /// address.
    bool is_listening_to(const IPAddress &multicast_address, const IPAddress &source_address) const
    {
        IgmpFilterRecord *record_ptr = records.findp(multicast_address);
        if (record_ptr == nullptr)
        {
            return false;
        }

        bool is_excluding = record_ptr->filter_mode == IgmpFilterMode::Exclude;
        for (const auto &item : record_ptr->source_addresses)
        {
            if (item == source_address)
            {
                return !is_excluding;
            }
        }
        return is_excluding;
    }

  private:
    HashMap<IPAddress, IgmpFilterRecord> records;
};

CLICK_ENDDECLS

#endif
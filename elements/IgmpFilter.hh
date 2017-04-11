#ifndef IGMP_FILTER
#define IGMP_FILTER

#include <click/config.h>
#include <click/hashmap.hh>
#include <click/vector.hh>
#include <clicknet/ip.h>

CLICK_DECLS

enum class IgmpFilterMode
{
    Include,
    Exclude
};

/// A "filter" for IGMP packets. It decides which addresses are listened to and which are not.
class IgmpFilter
{
  private:
    struct IgmpFilterRecord
    {
        bool is_excluding;
        Vector<IPAddress> source_addresses;
    };

  public:
    /// Listens to the given multicast address. A list of source addresses are either explicitly included
    /// or excluded.
    void listen(const IPAddress &multicast_address, IgmpFilterMode filter_mode, const Vector<IPAddress> &source_addresses)
    {
        IgmpFilterRecord *record_ptr;
        if (!records.findp(multicast_address))
        {
            records.insert(multicast_address, IgmpFilterRecord());
            record_ptr = records.findp(multicast_address);
        }
        record_ptr->is_excluding = filter_mode == IgmpFilterMode::Exclude;
        record_ptr->source_addresses = source_addresses;
    }

    /// Joins the given multicast address.
    void join(const IPAddress &multicast_address)
    {
        listen(multicast_address, IgmpFilterMode::Exclude, Vector<IPAddress>());
    }

    /// Leaves the given multicast address.
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

        for (const auto &item : record_ptr->source_addresses)
        {
            if (item == source_address)
            {
                return !record_ptr->is_excluding;
            }
        }
        return record_ptr->is_excluding;
    }

  private:
    HashMap<IPAddress, IgmpFilterRecord> records;
};

CLICK_ENDDECLS

#endif
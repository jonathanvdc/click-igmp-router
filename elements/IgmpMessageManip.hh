#pragma once

#include <click/config.h>
#include "IgmpMemberFilter.hh"
#include "IgmpMessage.hh"

CLICK_DECLS

/// Represents a parsed IGMP version 3 group record with no auxiliary data.
struct IgmpV3GroupRecord
{
    /// Creates an empty IGMP version 3 group record.
    IgmpV3GroupRecord()
        : type(), multicast_address(), source_addresses()
    {
    }

    /// Creates an IGMP version 3 group record that is equivalent to the specified
    /// filter record. A Boolean tells if the group record is supposed to indicate
    /// a change.
    IgmpV3GroupRecord(const IPAddress &multicast_address, const IgmpFilterRecord &record, bool is_change)
        : multicast_address(multicast_address), source_addresses(record.source_addresses)
    {
        type = is_change
                   ? (record.filter_mode == IgmpFilterMode::Include
                          ? IgmpV3GroupRecordType::ChangeToIncludeMode
                          : IgmpV3GroupRecordType::ChangeToExcludeMode)
                   : (record.filter_mode == IgmpFilterMode::Include
                          ? IgmpV3GroupRecordType::ModeIsInclude
                          : IgmpV3GroupRecordType::ModeIsExclude);
    }

    /// The record type.
    IgmpV3GroupRecordType type;

    /// The record's multicast address.
    IPAddress multicast_address;

    /// The record's list of source addresses.
    Vector<IPAddress> source_addresses;

    /// Tests if this IGMP version 3 group record indicates a change.
    bool is_change() const
    {
        switch (type)
        {
        case IgmpV3GroupRecordType::ModeIsInclude:
        case IgmpV3GroupRecordType::ModeIsExclude:
            return false;
        default:
            return true;
        }
    }

    /// Gets the size of this record, in bytes.
    size_t get_size() const
    {
        IgmpV3GroupRecordHeader header;
        header.number_of_sources = htons(source_addresses.size());
        return sizeof(IgmpV3GroupRecordHeader) + header.get_payload_size();
    }

    /// Writes this record to the given buffer.
    /// The address just past the last byte of the record is returned.
    unsigned char *write(unsigned char *buffer) const
    {
        // Create a header.
        IgmpV3GroupRecordHeader header;
        header.type = type;
        header.number_of_sources = htons(source_addresses.size());
        header.multicast_address = multicast_address.addr();

        // Write the header to the buffer.
        *((IgmpV3GroupRecordHeader *)buffer) = header;
        buffer += sizeof(IgmpV3GroupRecordHeader);

        // Write the source addresses.
        for (const auto &ip_address : source_addresses)
        {
            *((uint32_t *)buffer) = ip_address.addr();
            buffer += sizeof(uint32_t);
        }

        return buffer;
    }

    /// Reads an IGMP version 3 group record from the given buffer and advances
    /// the buffer pointer by the group record's size. Auxiliary data is ignored.
    static IgmpV3GroupRecord read(const unsigned char *(&buffer))
    {
        IgmpV3GroupRecord result;

        // Parse the header.
        auto header_ptr = reinterpret_cast<const IgmpV3GroupRecordHeader *>(buffer);
        result.type = header_ptr->type;
        result.multicast_address = IPAddress(header_ptr->multicast_address);
        uint16_t number_of_sources = ntohs(header_ptr->number_of_sources);
        uint8_t aux_data_length = header_ptr->aux_data_length;
        buffer += sizeof(IgmpV3GroupRecordHeader);

        // Parse the source addresses.
        for (uint16_t i = 0; i < number_of_sources; i++)
        {
            uint32_t addr = *(reinterpret_cast<const uint32_t *>(buffer));
            buffer += sizeof(uint32_t);
            result.source_addresses.push_back(IPAddress(addr));
        }

        // Skip the auxiliary data.
        buffer += sizeof(uint32_t) * aux_data_length;

        return result;
    }

    String get_type_string() const
    {
        switch (type)
        {
        case IgmpV3GroupRecordType::ModeIsInclude:
            return "mode-is-include";
        case IgmpV3GroupRecordType::ModeIsExclude:
            return "mode-is-exclude";
        case IgmpV3GroupRecordType::ChangeToIncludeMode:
            return "change-to-include";
        case IgmpV3GroupRecordType::ChangeToExcludeMode:
            return "change-to-exclude";
        default:
            return "unknown (0x" + String::make_numeric((String::uint_large_t)type, 16) + ")";
        }
    }

    String to_string() const
    {
        return "IGMPv3 group record: type: " +
               get_type_string() + ", multicast address: " +
               multicast_address.unparse() + ", " +
               String(source_addresses.size()) + " source addresses.";
    }
};

/// Represents a parsed IGMP version 3 membership report.
struct IgmpV3MembershipReport
{
    /// The membership report's group records.
    Vector<IgmpV3GroupRecord> group_records;

    /// Gets the size of this report, in bytes.
    size_t get_size() const
    {
        size_t result = sizeof(IgmpV3MembershipReportHeader);
        for (const auto &record : group_records)
        {
            result += record.get_size();
        }
        return result;
    }

    /// Writes this record to the given buffer.
    /// The address just past the last byte of the record is returned.
    unsigned char *write(unsigned char *buffer) const
    {
        // Create a header.
        IgmpV3MembershipReportHeader header;
        header.type = igmp_v3_membership_report_type;
        header.number_of_group_records = htons(group_records.size());

        // Write the header to the buffer.
        *((IgmpV3MembershipReportHeader *)buffer) = header;
        buffer += sizeof(IgmpV3MembershipReportHeader);

        // Write the group records.
        for (const auto &record : group_records)
        {
            record.write(buffer);
        }

        return buffer;
    }

    /// Reads an IGMP version 3 group record from the given buffer and advances
    /// the buffer pointer by the group record's size. Auxiliary data is ignored.
    static IgmpV3MembershipReport read(const unsigned char *(&buffer))
    {
        IgmpV3MembershipReport result;

        // Parse the header.
        auto header_ptr = reinterpret_cast<const IgmpV3MembershipReportHeader *>(buffer);
        uint16_t number_of_group_records = ntohs(header_ptr->number_of_group_records);
        buffer += sizeof(IgmpV3MembershipReportHeader);

        // Parse the group records.
        for (uint16_t i = 0; i < number_of_group_records; i++)
        {
            result.group_records.push_back(IgmpV3GroupRecord::read(buffer));
        }

        return result;
    }
};

/// Flags for IGMP membership queries.
struct IgmpMembershipQueryFlags
{
    IgmpMembershipQueryFlags()
        : resv(), suppress_router_side_processing(), robustness_variable()
    {
    }

    IgmpMembershipQueryFlags(uint8_t flags)
        : resv((flags & 0xF0) >> 4), suppress_router_side_processing((flags & 0x08) == 0x08), robustness_variable(flags & 0x07)
    {
    }

    /// The Resv field is set to zero on transmission, and ignored on
    /// reception.
    uint8_t resv;

    /// The Suppress Router-Side Processing aka S Flag.
    /// When set to one, the S Flag indicates to any receiving multicast
    /// routers that they are to suppress the normal timer updates they
    /// perform upon hearing a Query. It does not, however, suppress the
    /// querier election or the normal "host-side" processing of a Query that
    /// a router may be required to perform as a consequence of itself being
    /// a group member.
    bool suppress_router_side_processing;

    /// The Querier’s Robustness Variable aka QRV.
    /// If non-zero, the QRV field contains the [Robustness Variable] value
    /// used by the querier, i.e., the sender of the Query. If the querier’s
    /// [Robustness Variable] exceeds 7, the maximum value of the QRV field,
    /// the QRV is set to zero. Routers adopt the QRV value from the most
    /// recently received Query as their own [Robustness Variable] value,
    /// unless that most recently received QRV was zero, in which case the
    /// receivers use the default [Robustness Variable] value specified in
    /// section 8.1 or a statically configured value.
    uint8_t robustness_variable;

    /// Converts this set of membership query flags to a byte.
    uint8_t to_byte() const
    {
        return (resv << 4)
            | (suppress_router_side_processing ? 0x08 : 0x00)
            | (robustness_variable & 0x07);
    }
};

/// Represents a parsed IGMP membership query.
struct IgmpMembershipQuery
{
    IgmpMembershipQuery()
        : max_resp_time(), group_address(), suppress_router_side_processing(),
          robustness_variable(), query_interval(), source_addresses()
    {
    }

    /// Specifies the maximum amount of time allowed before sending a responding report.
    unsigned int max_resp_time;

    /// The Group Address field is set to zero when sending a General Query,
    /// and set to the IP multicast address being queried when sending a
    /// Group-Specific Query or Group-and-Source-Specific Query).
    IPAddress group_address;

    /// The Suppress Router-Side Processing aka S Flag.
    /// When set to one, the S Flag indicates to any receiving multicast
    /// routers that they are to suppress the normal timer updates they
    /// perform upon hearing a Query. It does not, however, suppress the
    /// querier election or the normal "host-side" processing of a Query that
    /// a router may be required to perform as a consequence of itself being
    /// a group member.
    bool suppress_router_side_processing;

    /// The Querier’s Robustness Variable aka QRV.
    /// If non-zero, the QRV field contains the [Robustness Variable] value
    /// used by the querier, i.e., the sender of the Query. If the querier’s
    /// [Robustness Variable] exceeds 7, the maximum value of the QRV field,
    /// the QRV is set to zero. Routers adopt the QRV value from the most
    /// recently received Query as their own [Robustness Variable] value,
    /// unless that most recently received QRV was zero, in which case the
    /// receivers use the default [Robustness Variable] value specified in
    /// section 8.1 or a statically configured value.
    uint8_t robustness_variable;

    /// The Querier’s Query Interval Interval field specifies the [Query
    /// Interval] used by the querier.
    unsigned int query_interval;

    /// The source addresses present in this query.
    Vector<IPAddress> source_addresses;

    /// Tests if this membership query is a general query.
    bool is_general_query() const
    {
        return group_address == IPAddress();
    }

    /// Gets the size of this query, in bytes.
    size_t get_size() const
    {
        return sizeof(IgmpMembershipQueryHeader) + source_addresses.size() * sizeof(uint32_t);
    }

    /// Writes this query to the given buffer.
    /// The address just past the last byte of the record is returned.
    unsigned char *write(unsigned char *buffer) const
    {
        // Create a header.
        IgmpMembershipQueryHeader header;
        header.type = igmp_membership_query_type;
        header.max_resp_code = igmp_value_to_code(max_resp_time);
        header.group_address = group_address.addr();
        IgmpMembershipQueryFlags flags;
        flags.suppress_router_side_processing = suppress_router_side_processing;
        flags.robustness_variable = robustness_variable;
        header.flags = flags.to_byte();
        header.query_interval_code = igmp_value_to_code(query_interval);
        header.number_of_sources = htons(source_addresses.size());

        // Write the header to the buffer.
        *((IgmpMembershipQueryHeader *)buffer) = header;
        buffer += sizeof(IgmpMembershipQueryHeader);

        // Write the source addresses.
        for (const auto &ip_address : source_addresses)
        {
            *((uint32_t *)buffer) = ip_address.addr();
            buffer += sizeof(uint32_t);
        }

        return buffer;
    }

    /// Reads an IGMP membership query from the given buffer and advances
    /// the buffer pointer by the group query's size.
    static IgmpMembershipQuery read(const unsigned char *(&buffer))
    {
        IgmpMembershipQuery result;

        // Parse the header.
        auto header_ptr = reinterpret_cast<const IgmpMembershipQueryHeader *>(buffer);
        result.max_resp_time = header_ptr->get_max_resp_time();
        result.group_address = IPAddress(header_ptr->group_address);
        IgmpMembershipQueryFlags flags{header_ptr->flags};
        result.suppress_router_side_processing = flags.suppress_router_side_processing;
        result.robustness_variable = flags.robustness_variable;
        result.query_interval = header_ptr->get_query_interval();
        uint16_t number_of_sources = ntohs(header_ptr->number_of_sources);
        buffer += sizeof(IgmpMembershipQueryHeader);

        // Parse the source addresses.
        for (uint16_t i = 0; i < number_of_sources; i++)
        {
            uint32_t addr = *(reinterpret_cast<const uint32_t *>(buffer));
            buffer += sizeof(uint32_t);
            result.source_addresses.push_back(IPAddress(addr));
        }

        return result;
    }
};

CLICK_ENDDECLS
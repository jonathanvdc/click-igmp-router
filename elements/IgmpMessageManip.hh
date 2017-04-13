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

CLICK_ENDDECLS
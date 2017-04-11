#pragma once

#include <click/config.h>
#include <clicknet/ip.h>

/// The type of IGMP membership query messages.
const uint8_t igmp_membership_query_type = 0x11;

/// The type of IGMP version 3 membership report messages.
const uint8_t igmp_v3_membership_report_type = 0x22;

/// Converts an IGMP code to an integer value as follows:
///
///     * If Code < 128, return Max Resp Code
///
///     * If Code >= 128, Code represents a floating-point
///       value as follows:
///
///        0 1 2 3 4 5 6 7
///       +-+-+-+-+-+-+-+-+
///       |1| exp | mant |
///       +-+-+-+-+-+-+-+-+
///
///       return (mant | 0x10) << (exp + 3)
inline unsigned int igmp_code_to_value(uint8_t code)
{
    if (code < 128)
    {
        return code;
    }
    else
    {
        unsigned int mantissa = code & 0x0F;
        unsigned int exponent = code & 0x70;
        return (mantissa | 0x10) << (exponent + 3);
    }
}

/// Describes the header of an IGMP membership query message.
struct IgmpMembershipQueryHeader
{
    /// The IGMP membership query message's type.
    /// This should always equal igmp_membership_query_type (0x11).
    uint8_t type : 8;

    /// Specifies the maximum amount of time allowed before sending a responding report.
    /// The actual time allowed, called the Max Resp Time, is represented in units of 1/10
    /// second and is derived from the Max Resp Code as follows:
    ///
    ///     * If Max Resp Code < 128, Max Resp Time = Max Resp Code
    ///
    ///     * If Max Resp Code >= 128, Max Resp Code represents a floating-point
    ///       value as follows:
    ///
    ///        0 1 2 3 4 5 6 7
    ///       +-+-+-+-+-+-+-+-+
    ///       |1| exp | mant |
    ///       +-+-+-+-+-+-+-+-+
    ///
    ///       Max Resp Time = (mant | 0x10) << (exp + 3)
    uint8_t max_resp_code : 8;

    /// The Checksum is the 16-bit one’s complement of the one’s complement
    /// sum of the whole IGMP message (the entire IP payload). For computing
    /// the checksum, the Checksum field is set to zero. When receiving
    /// packets, the checksum MUST be verified before processing a packet.
    uint16_t checksum : 16;

    /// The Group Address field is set to zero when sending a General Query,
    /// and set to the IP multicast address being queried when sending a
    /// Group-Specific Query or Group-and-Source-Specific Query).
    IPAddress group_address;

    /// The Resv field is set to zero on transmission, and ignored on
    /// reception.
    uint8_t resv : 4;

    /// The Suppress Router-Side Processing aka S Flag.
    /// When set to one, the S Flag indicates to any receiving multicast
    /// routers that they are to suppress the normal timer updates they
    /// perform upon hearing a Query. It does not, however, suppress the
    /// querier election or the normal "host-side" processing of a Query that
    /// a router may be required to perform as a consequence of itself being
    /// a group member.
    bool suppress_router_side_processing : 1;

    /// The Querier’s Robustness Variable aka QRV.
    /// If non-zero, the QRV field contains the [Robustness Variable] value
    /// used by the querier, i.e., the sender of the Query. If the querier’s
    /// [Robustness Variable] exceeds 7, the maximum value of the QRV field,
    /// the QRV is set to zero. Routers adopt the QRV value from the most
    /// recently received Query as their own [Robustness Variable] value,
    /// unless that most recently received QRV was zero, in which case the
    /// receivers use the default [Robustness Variable] value specified in
    /// section 8.1 or a statically configured value.
    uint8_t robustness_variable : 3;

    /// The Querier’s Query Interval Code aka QQIC.
    /// The Querier’s Query Interval Code field specifies the [Query
    /// Interval] used by the querier. The actual interval, called the
    /// Querier’s Query Interval (QQI), is represented in units of seconds
    /// and is derived from the Querier’s Query Interval Code as follows:
    ///
    ///     * If QQIC < 128, QQI = QQIC
    ///
    ///     * If QQIC >= 128, QQIC represents a floating-point value as follows:
    ///
    ///        0 1 2 3 4 5 6 7
    ///       +-+-+-+-+-+-+-+-+
    ///       |1| exp | mant |
    ///       +-+-+-+-+-+-+-+-+
    ///
    ///       QQI = (mant | 0x10) << (exp + 3)
    uint8_t query_interval_code : 8;

    /// The Number of Sources (N) field specifies how many source addresses
    /// are present in the Query. This number is zero in a General Query or
    /// a Group-Specific Query, and non-zero in a Group-and-Source-Specific
    /// Query. This number is limited by the MTU of the network over which
    /// the Query is transmitted. For example, on an Ethernet with an MTU of
    /// 1500 octets, the IP header including the Router Alert option consumes
    /// 24 octets, and the IGMP fields up to including the Number of Sources
    /// (N) field consume 12 octets, leaving 1464 octets for source
    /// addresses, which limits the number of source addresses to 366
    /// (1464/4).
    uint16_t number_of_sources : 16;

    /// Computes the Max Resp Time for this IGMP membership query message.
    unsigned int get_max_resp_time() const
    {
        return igmp_code_to_value(max_resp_code);
    }

    /// Computes the Querier’s Query Interval for this IGMP membership query message.
    unsigned int get_query_interval() const
    {
        return igmp_code_to_value(query_interval_code);
    }
} CLICK_SIZE_PACKED_ATTRIBUTE;

/// Describes the header of an IGMP version 3 membership report message.
///
/// Version 3 Membership Reports are sent by IP systems to report (to
/// neighboring routers) the current multicast reception state, or
/// changes in the multicast reception state, of their interfaces.
struct IgmpV3MembershipReportHeader
{
    /// The IGMP membership query message's type.
    /// This should always equal igmp_v3_membership_report_type (0x22).
    uint8_t type;

    /// The first Reserved field. Reserved fields are set to zero on
    /// transmission and ignored on reception.
    uint8_t reserved_one;

    /// The Checksum is the 16-bit one’s complement of the one’s complement
    /// sum of the whole IGMP message (the entire IP payload). For computing
    /// the checksum, the Checksum field is set to zero. When receiving
    /// packets, the checksum MUST be verified before processing a message.
    uint16_t checksum;

    /// The second Reserved field. Reserved fields are set to zero on
    /// transmission and ignored on reception.
    uint16_t reserved_two;

    /// The Number of Group Records (M) field specifies how many Group
    /// Records are present in this Report.
    uint16_t number_of_group_records;
} CLICK_SIZE_PACKED_ATTRIBUTE;

/// Computes an IGMP checksum for the IGMP message with the given data and size.
uint16_t compute_igmp_checksum(char *data, size_t size)
{
    size_t size_in_shorts = size / 2;
    uint16_t* data_copy = new uint16_t[size_in_shorts];
    memcpy(data_copy, data, size);

    auto header = (IgmpMembershipQueryHeader *)data_copy;
    header->checksum = 0;

    uint16_t ones_complement_sum = 0;
    for (size_t i = 0; i < size_in_shorts; i++)
    {
        ones_complement_sum += ~ntohs(data_copy[i]);
    }

    delete[] data_copy;
    return ~ones_complement_sum;
}
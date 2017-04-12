// Accepts IGMP packets and encapsulates them in IP packets.

elementclass IgmpIpEncap {
	$src_ip |

	// According to the spec:
	//
	// IGMP messages are encapsulated in IPv4 datagrams, with an IP protocol
	// number of 2. Every IGMP message described in this document is sent
	// with an IP Time-to-Live of 1, IP Precedence of Internetwork Control
	// (e.g., Type of Service 0xc0), and carries an IP Router Alert option
	// [RFC-2113] in its IP header.

	// TODO: set the IP Router Alert option

	input
		-> IPEncap(igmp, $src_ip, DST_ANNO, TTL 1, TOS 0xc0)
		-> output;
}

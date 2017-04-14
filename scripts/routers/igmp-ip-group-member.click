// An IGMP-IP group member implementation.

require(library igmp-ip-encap.click)

elementclass IgmpIpGroupMember {
	$src_ip |

	// Description of ports:
	//
	//     * Input:
	//         0. IP packets.
	//
	//     * Output:
	//         0. IGMP-IP packets for the network.
	//         1. Multicast IP packets for the host.
	//         2. Other IP packets.
	//

	igmp :: IgmpGroupMember()
		-> IgmpSetChecksum
		-> IgmpIpEncap($src_ip)
		-> [0]output;

	// IGMP tells us an IP packet is a multicast packet for the host.
	igmp[1]
		-> IPPrint("IGMP group member: delivering")
		-> [1]output;

	// IGMP tells us that it's something else.
	igmp[2]
		-> IPPrint("IGMP group member: ignoring")
		-> [2]output;

	// Receive IP packets.
	input[0]
		-> CheckIPHeader
		-> ip_classifier :: IPClassifier(ip proto igmp, -)
		// IGMP packets have their IP headers stripped and are
		// sent to the router as raw IGMP packets.
		-> IPPrint("IGMP router: accepting IGMP packet")
		-> StripIPHeader
		-> [1]igmp;

	// Tests if the host is interested in this packet.
	ip_classifier[1]
		-> [0]igmp;
}

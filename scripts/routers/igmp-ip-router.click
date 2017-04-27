// An IGMP-IP router implementation for a single network.

require(library igmp-ip-encap.click)

elementclass IgmpIpRouter {
	$src_ip |

	// Description of ports:
	//
	//     * Input:
	//         0. IP packets from the network managed by this router instance.
	//         1. IP packets from other networks.
	//
	//     * Output:
	//         0. (Fragmented) IP packets for the network managed by this router instance.
	//         1. IP error packets.
	//

	igmp :: IgmpRouter(ADDRESS $src_ip)
		-> IgmpSetChecksum
		-> IgmpIpEncap($src_ip)
		-> IPFragmenter(1500)
		-> [0]output;

	// IGMP tells us an IP packet is a multicast packet for the network.
	igmp[1]
		-> DropBroadcasts
		-> IPPrint("IGMP router: forwarding")
		-> ipgw :: IPGWOptions($src_ip)
		-> FixIPSrc($src_ip)
		-> ttl :: DecIPTTL
		-> frag :: IPFragmenter(1500)
		-> [0]output;

	ipgw[1]
		-> ICMPError($src_ip, parameterproblem)
		-> [1]output;

	ttl[1]
		-> ICMPError($src_ip, timeexceeded)
		-> [1]output;

	frag[1]
		-> ICMPError($src_ip, unreachable, needfrag)
		-> [1]output;

	// IGMP tells us that it's something else. Better drop it then.
	igmp[2]
		-> IPPrint("IGMP router: dropping")
		-> Discard;

	// Receive IGMP packets.
	input[0]
		-> CheckIPHeader
		-> ip_classifier :: IPClassifier(ip proto igmp, -)
		// IGMP packets have their IP headers stripped and are
		// sent to the router as raw IGMP packets.
		-> IPPrint("IGMP router: accepting IGMP packet")
		-> MarkIPHeader
		-> StripIPHeader
		-> checksum_check :: IgmpCheckChecksum
		-> [1]igmp;

	// At best, forward the packet. Don't read IGMP packets from this source.
	input[1]
		-> [0]igmp;

	// We're dealing with a non-IGMP packet from the network managed by this router.
	// Note that this means that the IP packet will arrive in this IGMP router _twice_:
	// once as a packet from the managed network and once as a packet from any network.
	//
	// We could forward the packet here, but then we'd duplicate it -- and we don't want
	// that. Instead, we'll just discard it and wait for the same packet to arrive from
	// 'input[1]'.
	ip_classifier[1]
		-> Discard;

	// The spec's not all that clear on what we should do with IGMP packets that have invalid checksums.
	// All it says is:
	//
	//     [...] When receiving packets, the checksum MUST be verified before processing a packet.
	//
	// But that's not very helpful.
	//
	// SPEC INTERPRETATION: we should ignore IGMP packets with invalid checksums and assume that they have
	// been corrupted over the course of their transmission.
	checksum_check[1]
		-> Print("IGMP router: ignoring IGMP packet with invalid checksum.")
		-> Discard;
}

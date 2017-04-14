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
	//         0. IP packets for the network managed by this router instance.
	//         1. Erroneous IP packets.
	//

	igmp :: IgmpRouter()
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
		-> StripIPHeader
		-> [1]igmp;

	// At best, forward the packet. Don't read IGMP packets.
	input[1]
		-> [0]igmp;

	// Non-IGMP IP packets are sent to the IGMP router, which decides
	// if they are to be broadcast to the managed network.
	ip_classifier[1]
		-> [0]igmp;
}

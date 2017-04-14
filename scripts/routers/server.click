
// Output configuration: 
//
// Packets for the network are put on output 0
// Packets for the host are put on output 1

require(library igmp-ip-group-member.click)

elementclass Server {
	$address, $gateway |

	frag :: IPFragmenter(1500)
		-> arpq :: ARPQuerier($address)
		-> output;

	igmp :: IgmpIpGroupMember($address:ip)
		-> frag;

	// IGMP tells us the packet is a multicast packet for an address to which
	// we've subscribed.
	igmp[1]
		-> [1]output;

	// IGMP tells us that it's something else.
	igmp[2]
		-> rt :: StaticIPLookup(
					$address:ip/32 0,
					$address:ipnet 0,
					0.0.0.0/0.0.0.0 $gateway 1)
		-> [1]output;

	ip :: Strip(14)
		-> CheckIPHeader()
		-> igmp;
	
	rt[1]
		-> DropBroadcasts
		-> ipgw :: IPGWOptions($address)
		-> FixIPSrc($address)
		-> ttl :: DecIPTTL
		-> frag;

	ipgw[1]
		-> ICMPError($address, parameterproblem)
		-> output;
	
	ttl[1]
		-> ICMPError($address, timeexceeded)
		-> output; 

	frag[1]
		-> ICMPError($address, unreachable, needfrag)
		-> output;

	// Incoming Packets
	input
		-> HostEtherFilter($address)
		-> in_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800)
		-> arp_res :: ARPResponder($address)
		-> output;

	in_cl[1]
		-> [1]arpq;
	
	in_cl[2]
		-> ip;
}

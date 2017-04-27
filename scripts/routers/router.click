// Router with three interfaces
// The input/output configuration is as follows:
//
// Input:
//	[0]: packets received on the 192.168.1.0/24 network
//	[1]: packets received on the 192.168.2.0/24 network
//	[2]: packets received on the 192.168.3.0/24 network
//
// Output:
//	[0]: packets sent to the 192.168.1.0/24 network
//	[1]: packets sent to the 192.168.2.0/24 network
//	[2]: packets sent to the 192.168.3.0/24 network
//  [3]: packets destined for the router itself

require(library igmp-ip-router.click)

elementclass Router {
	$server_address, $client1_address, $client2_address |

	// According to the spec:
	//
	//     Multicast routers implementing IGMPv3 keep state per group per
	//     attached network.
	//
	// IgmpRouter/IgmpIpRouter do that for just one network. So we'll create three.

	igmp_multicast_server :: IgmpIpRouter($server_address:ip);
	igmp_client1 :: IgmpIpRouter($client1_address:ip);
	igmp_client2 :: IgmpIpRouter($client2_address:ip);

	igmp_in_switch :: PaintSwitch;
	igmp_in_switch[0] -> Discard;
	igmp_in_switch[1] -> igmp_multicast_server;
	igmp_in_switch[2] -> igmp_client1;
	igmp_in_switch[3] -> igmp_client2;

	igmp_in_tee :: Tee(5);
	igmp_in_tee[0] -> [1]igmp_multicast_server;
	igmp_in_tee[1] -> [1]igmp_client1;
	igmp_in_tee[2] -> [1]igmp_client2;
	igmp_in_tee[3] -> igmp_in_switch;
	igmp_in_tee[4]
		-> rt :: StaticIPLookup(
			$server_address:ip/32 0,
			$client1_address:ip/32 0,
			$client2_address:ip/32 0,
			$server_address:ipnet 1,
			$client1_address:ipnet 2,
			$client2_address:ipnet 3);

	igmp_multicast_server[1] -> rt;
	igmp_client1[1] -> rt;
	igmp_client2[1] -> rt;

	// ARP responses are copied to each ARPQuerier and the host.
	arpt :: Tee (3);

	// Shared IP input path and routing table
	ip :: Strip(14)
		-> CheckIPHeader
		-> igmp_in_tee;
	
	// Input and output paths for interface 0
	input
		-> HostEtherFilter($server_address)
		-> server_class :: Classifier(12/0806 20/0001, 12/0806 20/0002, -)
		-> ARPResponder($server_address)
		-> output;

	igmp_multicast_server
		-> server_arpq :: ARPQuerier($server_address)
		-> output;

	server_class[1]
		-> arpt
		-> [1]server_arpq;

	server_class[2]
		-> Paint(1)
		-> ip;

	// Input and output paths for interface 1
	input[1]
		-> HostEtherFilter($client1_address)
		-> client1_class :: Classifier(12/0806 20/0001, 12/0806 20/0002, -)
		-> ARPResponder($client1_address)
		-> [1]output;

	igmp_client1
		-> client1_arpq :: ARPQuerier($client1_address)
		-> [1]output;

	client1_class[1]
		-> arpt[1]
		-> [1]client1_arpq;

	client1_class[2]
		-> Paint(2)
		-> ip;

	// Input and output paths for interface 2
	input[2]
		-> HostEtherFilter($client2_address)
		-> client2_class :: Classifier(12/0806 20/0001, 12/0806 20/0002, -)
		-> ARPResponder($client2_address)
		-> [2]output;

	igmp_client2
		-> client2_arpq :: ARPQuerier($client2_address)
		-> [2]output;

	client2_class[1]
		-> arpt[2]
		-> [1]client2_arpq;

	client2_class[2]
		-> Paint(3)
		-> ip;
	
	// Local delivery
	rt[0]
		-> [3]output
	
	// Forwarding paths per interface
	rt[1]
		-> DropBroadcasts
		-> server_paint :: PaintTee(1)
		-> server_ipgw :: IPGWOptions($server_address)
		-> FixIPSrc($server_address)
		-> server_ttl :: DecIPTTL
		-> server_frag :: IPFragmenter(1500)
		-> server_arpq;
	
	server_paint[1]
		-> ICMPError($server_address, redirect, host)
		-> rt;

	server_ipgw[1]
		-> ICMPError($server_address, parameterproblem)
		-> rt;

	server_ttl[1]
		-> ICMPError($server_address, timeexceeded)
		-> rt;

	server_frag[1]
		-> ICMPError($server_address, unreachable, needfrag)
		-> rt;
	

	rt[2]
		-> DropBroadcasts
		-> client1_paint :: PaintTee(2)
		-> client1_ipgw :: IPGWOptions($client1_address)
		-> FixIPSrc($client1_address)
		-> client1_ttl :: DecIPTTL
		-> client1_frag :: IPFragmenter(1500)
		-> client1_arpq;
	
	client1_paint[1]
		-> ICMPError($client1_address, redirect, host)
		-> rt;

	client1_ipgw[1]
		-> ICMPError($client1_address, parameterproblem)
		-> rt;

	client1_ttl[1]
		-> ICMPError($client1_address, timeexceeded)
		-> rt;

	client1_frag[1]
		-> ICMPError($client1_address, unreachable, needfrag)
		-> rt;


	rt[3]
		-> DropBroadcasts
		-> client2_paint :: PaintTee(2)
		-> client2_ipgw :: IPGWOptions($client2_address)
		-> FixIPSrc($client2_address)
		-> client2_ttl :: DecIPTTL
		-> client2_frag :: IPFragmenter(1500)
		-> client2_arpq;
	
	client2_paint[1]
		-> ICMPError($client2_address, redirect, host)
		-> rt;

	client2_ipgw[1]
		-> ICMPError($client2_address, parameterproblem)
		-> rt;

	client2_ttl[1]
		-> ICMPError($client2_address, timeexceeded)
		-> rt;

	client2_frag[1]
		-> ICMPError($client2_address, unreachable, needfrag)
		-> rt;
}


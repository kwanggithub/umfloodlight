package net.floodlightcontroller.bgproute;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class Rib {
	protected InetAddress routerId;
	protected InetAddress nextHop;
	protected int distance;
	
	Rib(InetAddress router_id, InetAddress nexthop) {
		this.routerId = router_id;
		this.nextHop = nexthop;
		this.distance = distance;
	}
	
	Rib(String router_id, String nexthop) {
		try {
			this.routerId = InetAddress.getByName(router_id);
		} catch (UnknownHostException e) {
			System.out.println("InetAddress exception");
		}
		try {
			this.nextHop = InetAddress.getByName(nexthop);
		} catch (UnknownHostException e) {
			System.out.println("InetAddress exception");
		}
	}
}

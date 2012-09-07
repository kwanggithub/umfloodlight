package net.floodlightcontroller.bgproute;

import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.resource.Delete;
import org.restlet.resource.ServerResource;

public class BgpRouteResource extends ServerResource {
	@Get("json")
	public String get(String fmJson) {
		String dest = (String) getRequestAttributes().get("dest");
		
		if (dest != null) {
			Prefix p = new Prefix(dest, 32);
			byte [] nexthop = BgpRoute.lookupRib(p.getAddress());
			if (nexthop != null) {
				System.out.println("Nexthop found:");
				Prefix n = new Prefix(nexthop, 32);
			} else {
				System.out.println("Nexthop does not exist");
			}
		} else {
			Ptree ptree = BgpRoute.getPtree();
		
			for (PtreeNode node = ptree.begin(); node != null; node = ptree.next(node)) {
				Prefix p_result = new Prefix(node.key, node.keyBits);
			}
		}
		
		return "[GET]";
	}
	@Post
	public String store(String fmJson) {
		Ptree ptree = BgpRoute.getPtree();

		String router_id = (String) getRequestAttributes().get("routerid");
		String prefix = (String) getRequestAttributes().get("prefix");
		String mask = (String) getRequestAttributes().get("mask");
		String nexthop = (String) getRequestAttributes().get("nexthop");
		
		Rib rib = new Rib(router_id, nexthop);
		
		Prefix p = new Prefix(prefix, Integer.valueOf(mask));
		PtreeNode node = ptree.acquire(p.getAddress(), p.masklen);
		if (node.rib != null) {
			node.rib = null;
			ptree.delReference(node);
		}
		node.rib = rib;

		return "[POST:" + router_id + ":" + prefix + ":" + mask + ":" + nexthop + "]";
	}
	
	@Delete
	public String delete(String fmJson) {
		Ptree ptree = BgpRoute.getPtree();
		
		String routerId = (String) getRequestAttributes().get("routerid");
		String prefix = (String) getRequestAttributes().get("prefix");
		String mask = (String) getRequestAttributes().get("mask");
		String nextHop = (String) getRequestAttributes().get("nexthop");
		
		Prefix p = new Prefix(prefix, Integer.valueOf(mask));
		PtreeNode node = ptree.lookup(p.getAddress(), p.masklen);
		if (node != null) {
			node.rib = null;
			ptree.delReference(node);
			ptree.delReference(node);
		}
		
		return "[DELETE:" + routerId + ":" + prefix + ":" + mask + ":" + nextHop + "]";
	}
}

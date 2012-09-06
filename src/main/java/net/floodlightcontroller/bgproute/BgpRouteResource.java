package net.floodlightcontroller.bgproute;

import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.resource.Delete;
import org.restlet.resource.ServerResource;

public class BgpRouteResource extends ServerResource {
	@Get("json")
	public String get(String fmJson) {
		Ptree ptree = BgpRoute.getPtree();
		
		for (PtreeNode node = ptree.begin(); node != null; node = ptree.next(node)) {
			Prefix p_result = new Prefix(node.key, node.keyBits);
		}
		
		return "[GET]";
	}
	@Post
	public String store(String fmJson) {
		Ptree ptree = BgpRoute.getPtree();

		String routerId = (String) getRequestAttributes().get("routerid");
		String prefix = (String) getRequestAttributes().get("prefix");
		String mask = (String) getRequestAttributes().get("mask");
		String nextHop = (String) getRequestAttributes().get("nexthop");
		
		Prefix p = new Prefix(prefix, Integer.valueOf(mask));
		ptree.acquire(p.getAddress(), p.masklen);
		
		return "[POST:" + routerId + ":" + prefix + ":" + mask + ":" + nextHop + "]";
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
			ptree.delReference(node);
			ptree.delReference(node);
		}
		
		return "[DELETE:" + routerId + ":" + prefix + ":" + mask + ":" + nextHop + "]";
	}
}

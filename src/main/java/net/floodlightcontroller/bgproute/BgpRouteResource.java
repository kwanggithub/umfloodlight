package net.floodlightcontroller.bgproute;

import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.resource.Delete;
import org.restlet.resource.ServerResource;

public class BgpRouteResource extends ServerResource {
	private String addrToString(byte [] addr) {
		String str = "";
		
		for (int i = 0; i < 4; i++) {
			int val = (addr[i] & 0xff);
			str += val;
			if (i != 3)
				str += ".";
		}
		
		return str;
	}
	
	@Get
	public String get(String fmJson) {
		String dest = (String) getRequestAttributes().get("dest");
		String output = "";
		IBgpRouteService bgpRoute = (IBgpRouteService)getContext().getAttributes().
                get(IBgpRouteService.class.getCanonicalName());
		
		if (dest != null) {
			Prefix p = new Prefix(dest, 32);
			if (p == null) {
				return "[GET]: dest address format is wrong";
			}
			byte [] nexthop = bgpRoute.lookupRib(p.getAddress());
			if (nexthop != null) {
				output += "{\"result\": \"" + addrToString(nexthop) + "\"}\n";
			} else {
				output += "{\"result\": \"Nexthop does not exist\"}\n";
			}
		} else {
			Ptree ptree = bgpRoute.getPtree();
			output += "{\n  \"rib\": [\n";
			boolean printed = false;
			for (PtreeNode node = ptree.begin(); node != null; node = ptree.next(node)) {
				if (node.rib == null) {
					continue;
				}
				if (printed == true) {
					output += ",\n";
				}
				output += "    {\"prefix\": \"" + addrToString(node.key) + "/" + node.keyBits +"\", ";
				output += "\"nexthop\": \"" + addrToString(node.rib.nextHop.getAddress()) +"\"}";
				printed = true;
			}
			//output += "{\"router_id\": \"" + addrToString(node.rib.routerId.getAddress()) +"\"}\n";
			output += "\n  ]\n}\n";
		}
		
		return output;
	}
	@Post
	public String store(String fmJson) {
        IBgpRouteService bgpRoute = (IBgpRouteService)getContext().getAttributes().
                get(IBgpRouteService.class.getCanonicalName());

	    Ptree ptree = bgpRoute.getPtree();

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

		return "[POST:" + router_id + ":" + prefix + ":" + mask + ":" + nexthop + "]\n";
	}
	
	@Delete
	public String delete(String fmJson) {
        IBgpRouteService bgpRoute = (IBgpRouteService)getContext().getAttributes().
                get(IBgpRouteService.class.getCanonicalName());

        Ptree ptree = bgpRoute.getPtree();
		
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
		
		return "[DELETE:" + routerId + ":" + prefix + ":" + mask + ":" + nextHop + "]\n";
	}
}

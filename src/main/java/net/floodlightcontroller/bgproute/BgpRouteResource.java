package net.floodlightcontroller.bgproute;

import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.resource.Delete;
import org.restlet.resource.ServerResource;

public class BgpRouteResource extends ServerResource {
	@Get("json")
	public String get(String fmJson) {
		return "[GET]";
	}
	@Post
	public String store(String fmJson) {
		String routerId = (String) getRequestAttributes().get("routerid");
		String prefix = (String) getRequestAttributes().get("prefix");
		String mask = (String) getRequestAttributes().get("mask");
		String nextHop = (String) getRequestAttributes().get("nexthop");
		return "[POST:" + routerId + ":" + prefix + ":" + mask + ":" + nextHop + "]";
	}
	
	@Delete
	public String delete(String fmJson) {
		String routerId = (String) getRequestAttributes().get("routerid");
		String prefix = (String) getRequestAttributes().get("prefix");
		String mask = (String) getRequestAttributes().get("mask");
		String nextHop = (String) getRequestAttributes().get("nexthop");
		return "[DELETE:" + routerId + ":" + prefix + ":" + mask + ":" + nextHop + "]";
	}
}

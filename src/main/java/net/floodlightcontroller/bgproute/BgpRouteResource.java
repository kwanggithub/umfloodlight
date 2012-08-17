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
		return "[POST]";
	}
	
	@Delete
	public String delete(String fmJson) {
		return "[DELETE]";
	}
}

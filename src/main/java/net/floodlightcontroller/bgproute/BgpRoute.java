package net.floodlightcontroller.bgproute;

import java.util.Collection;
import java.util.Map;
import java.util.ArrayList;
import java.util.HashMap;

import java.net.UnknownHostException;

import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.restserver.IRestApiService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BgpRoute implements IFloodlightModule, BgpRouteService {
	
	protected static Logger log = LoggerFactory.getLogger(BgpRoute.class);

	protected IFloodlightProviderService floodlightProvider;
	
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(BgpRouteService.class);
		return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> m = new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
		m.put(BgpRouteService.class, this);
		return m;
	}

	protected IRestApiService restApi;
	
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(BgpRouteService.class);
		return l;
	}

	protected Ptree ptree;
	
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		restApi = context.getServiceImpl(IRestApiService.class);

		// Test.
		if (false) {
			ptree = new Ptree(32);
			System.out.println("Here it is");
			Prefix p = new Prefix("128.0.0.0", 8);
			Prefix q = new Prefix("8.0.0.0", 8);
		
			ptree.acquire(p.getAddress(), p.masklen);
			ptree.acquire(q.getAddress(), q.masklen);
		
			System.out.println("Traverse start");
			for (PtreeNode node = ptree.begin(); node != null; node = ptree.next(node)) {
				Prefix p_result = new Prefix(node.key, node.keyBits);
			}
		
			PtreeNode n = ptree.lookup(p.getAddress(), p.masklen);
			if (n != null) {
				ptree.delReference(n);
				ptree.delReference(n);
			}
			System.out.println("Traverse start");
			for (PtreeNode node = ptree.begin(); node != null; node = ptree.next(node)) {
				Prefix p_result = new Prefix(node.key, node.keyBits);
			}
			
			n = ptree.lookup(q.getAddress(), q.masklen);
			if (n != null) {
				System.out.println("q refCount: " + n.refCount);
				ptree.delReference(n);
				ptree.delReference(n);
			}
			System.out.println("Traverse start");
			for (PtreeNode node = ptree.begin(); node != null; node = ptree.next(node)) {
				Prefix p_result = new Prefix(node.key, node.keyBits);
			}
		}
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		restApi.addRestletRoutable(new BgpRouteWebRoutable());
	}

	@Override
	public int getBuffer() {
		return 0;
	}
}

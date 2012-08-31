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

	protected Ptree rib;
	
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		restApi = context.getServiceImpl(IRestApiService.class);
		rib = new Ptree();
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

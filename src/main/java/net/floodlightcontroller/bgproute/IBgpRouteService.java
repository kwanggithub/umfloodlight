package net.floodlightcontroller.bgproute;

import net.floodlightcontroller.core.module.IFloodlightService;

public interface IBgpRouteService extends IFloodlightService {

    public byte[] lookupRib(byte[] dest);
    
    public Ptree getPtree();
    
}

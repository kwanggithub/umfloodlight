package net.floodlightcontroller.interdomainforwarding;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionDataLayerDestination;
import org.openflow.protocol.action.OFActionOutput;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.forwarding.Forwarding;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.topology.NodePortTuple;
import net.floodlightcontroller.util.MACAddress;

public class InterDomainForwarding extends Forwarding implements
        IFloodlightModule {
    protected static Logger log = LoggerFactory
            .getLogger(InterDomainForwarding.class);

    // KC constant for L3 handling
    public final String GW_PROXY_ARP_MACADDRESS = "12:34:56:78:90:12";

    // doProxyArp called when destination is external to SDN network

    protected void doProxyArp(IOFSwitch sw, OFPacketIn pi,
            FloodlightContext cntx) {
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
                IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

        // below KC temporary implementation - will move to new L3
        // forwarding
        // module later.

        // If arping for default gateway(s), isExternal==true
        // respond with proxy arp; otherwise, flood for now

        // retrieve arp to determine target IP address
        ARP arpRequest = (ARP) eth.getPayload();

        // if indeed target is gw, proxy arp with special mac address
        log.debug("KC L3 forwarding: see arp, IsExternal");

        // generate ARP reply
        byte[] proxyArp = MACAddress.valueOf(GW_PROXY_ARP_MACADDRESS).toBytes();

        IPacket arpReply = new Ethernet()
                .setSourceMACAddress(proxyArp)
                .setDestinationMACAddress(eth.getSourceMACAddress())
                .setEtherType(Ethernet.TYPE_ARP)
                .setVlanID(eth.getVlanID())
                .setPriorityCode(eth.getPriorityCode())
                .setPayload(
                        new ARP()
                                .setHardwareType(ARP.HW_TYPE_ETHERNET)
                                .setProtocolType(ARP.PROTO_TYPE_IP)
                                .setHardwareAddressLength((byte) 6)
                                .setProtocolAddressLength((byte) 4)
                                .setOpCode(ARP.OP_REPLY)
                                .setSenderHardwareAddress(proxyArp)
                                .setSenderProtocolAddress(
                                        arpRequest.getTargetProtocolAddress())
                                .setTargetHardwareAddress(
                                        eth.getSourceMACAddress())
                                .setTargetProtocolAddress(
                                        arpRequest.getSenderProtocolAddress()));

        // TODO: doDropFlow (as in VNF) to discard ARP request in
        // switch buffer

        // push ARP out
        pushPacket(arpReply, sw, OFPacketOut.BUFFER_ID_NONE, (short) 4,
                pi.getInPort(), cntx);
        log.debug("proxy ARP reply pushed");
        // this should cause a unicast packet's packetIn to come to
        // controller

        return;
    }
    
    protected FloodlightContext prepInterDomainForwarding(FloodlightContext cntx){
        
        log.debug("KC L3 forwarding: got the real payload");

        // query BgpRoute for the right gateway IP
        // To fix below with real value
        String gwIPAddressStr = "10.0.0.3";
        Integer gwIPAddress = IPv4.toIPv4Address(gwIPAddressStr);

        // Get gateway Device handler

        // retrieve all known devices from IDeviceService for search
        Collection<? extends IDevice> allDevices = deviceManager
                .getAllDevices();

        // search through all device list to identify src and dst device
        // with their IP addresses
        IDevice gwDevice = null;

        for (IDevice d : allDevices) {
            for (int i = 0; i < d.getIPv4Addresses().length; i++) {
                if (gwIPAddress.equals(d.getIPv4Addresses()[i])) {
                    gwDevice = d;
                    break;
                }
            }
        }

        if (gwDevice != null) {
            // overwrite dest device found by deviceManager/PktIn with
            // gw device
            IDeviceService.fcStore.put(cntx,
                    IDeviceService.CONTEXT_DST_DEVICE, gwDevice);

        } else {
            // if no known devices match the BgpRoute suggested gateway
            // IP, this is an error in BgpRoute to be handled

            log.debug("KC L3 forwarding: bad gw assigned");
        }
        
        return cntx;          
    }

    /**
     * Push routes for interdomain forwarding
     * 
     * @param route
     *            Route to push
     * @param match
     *            OpenFlow fields to match on
     * @param srcSwPort
     *            Source switch port for the first hop
     * @param dstSwPort
     *            Destination switch port for final hop
     * @param bufferId
     *            BufferId of the original PacketIn
     * @param cookie
     *            The cookie to set in each flow_mod
     * @param cntx
     *            The floodlight context
     * @param reqeustFlowRemovedNotifn
     *            if set to true then the switch would send a flow mod removal
     *            notification when the flow mod expires
     * @param doFlush
     *            if set to true then the flow mod would be immediately written
     *            to the switch
     * @param flowModCommand
     *            flow mod. command to use, e.g. OFFlowMod.OFPFC_ADD,
     *            OFFlowMod.OFPFC_MODIFY etc.
     * @return srcSwitchIincluded True if the source switch is included in this
     *         route
     */
    public boolean pushRoute(Route route, OFMatch match,
            Integer wildcard_hints, int bufferId, OFPacketIn pi,
            long pinSwitch, long cookie, FloodlightContext cntx,
            boolean reqeustFlowRemovedNotifn, boolean doFlush,
            short flowModCommand) {

        boolean srcSwitchIncluded = false;
        OFFlowMod fm = (OFFlowMod) floodlightProvider.getOFMessageFactory()
                .getMessage(OFType.FLOW_MOD);
        OFActionOutput action = new OFActionOutput();
        action.setMaxLength((short) 0xffff);
        List<OFAction> actions = new ArrayList<OFAction>();
        actions.add(action);

        fm.setIdleTimeout((short) 5)
                .setBufferId(OFPacketOut.BUFFER_ID_NONE)
                .setCookie(cookie)
                .setCommand(flowModCommand)
                .setMatch(match)
                .setActions(actions)
                .setLengthU(
                        OFFlowMod.MINIMUM_LENGTH
                                + OFActionOutput.MINIMUM_LENGTH);

        List<NodePortTuple> switchPortList = route.getPath();

        for (int indx = switchPortList.size() - 1; indx > 0; indx -= 2) {
            // indx and indx-1 will always have the same switch DPID.
            long switchDPID = switchPortList.get(indx).getNodeId();
            IOFSwitch sw = floodlightProvider.getSwitches().get(switchDPID);
            if (sw == null) {
                if (log.isWarnEnabled()) {
                    log.warn("Unable to push route, switch at DPID {} "
                            + "not available", switchDPID);
                }
                return srcSwitchIncluded;
            }

            // set the match.
            fm.setMatch(wildcard(match, sw, wildcard_hints));

            // set buffer id if it is the source switch
            if (1 == indx) {
                // Set the flag to request flow-mod removal notifications only
                // for the
                // source switch. The removal message is used to maintain the
                // flow
                // cache. Don't set the flag for ARP messages - TODO generalize
                // check
                if ((reqeustFlowRemovedNotifn)
                        && (match.getDataLayerType() != Ethernet.TYPE_ARP)) {
                    fm.setFlags(OFFlowMod.OFPFF_SEND_FLOW_REM);
                    match.setWildcards(fm.getMatch().getWildcards());
                }
            }

            short outPort = switchPortList.get(indx).getPortId();
            short inPort = switchPortList.get(indx - 1).getPortId();
            // set input and output ports on the switch
            fm.getMatch().setInputPort(inPort);
            ((OFActionOutput) fm.getActions().get(0)).setPort(outPort);

            // KC L3 handling
            IDevice dstDevice = IDeviceService.fcStore.get(cntx,
                    IDeviceService.CONTEXT_DST_DEVICE);
            List<OFAction> newActions = fm.getActions();

            if (indx == 1) {
            
                if (MACAddress.valueOf(fm.getMatch().getDataLayerDestination())
                        .equals(MACAddress.valueOf(GW_PROXY_ARP_MACADDRESS))) {
                    

                    OFAction rewriteAction = new OFActionDataLayerDestination(
                            MACAddress.valueOf(dstDevice.getMACAddress())
                                    .toBytes());

                    newActions.add(0, rewriteAction);
                    fm.setActions(newActions);
                    fm.setLengthU(fm.getLengthU() + rewriteAction.getLengthU());
                }
            } else {
                fm.getMatch().setDataLayerDestination(MACAddress.valueOf(dstDevice.getMACAddress())
                                    .toBytes());
            }

            try {
                counterStore.updatePktOutFMCounterStore(sw, fm);
                if (log.isTraceEnabled()) {
                    log.trace("Pushing Route flowmod routeIndx={} "
                            + "sw={} inPort={} outPort={}", new Object[] {
                            indx, sw, fm.getMatch().getInputPort(), outPort });
                }
                sw.write(fm, cntx);
                if (doFlush) {
                    sw.flush();
                }

                // Push the packet out the source switch
                if (sw.getId() == pinSwitch) {
                    // TODO: Instead of doing a packetOut here we could also
                    // send a flowMod with bufferId set....
                    pushPacket(sw, match, pi, outPort, cntx);
                    srcSwitchIncluded = true;
                }
            } catch (IOException e) {
                log.error("Failure writing flow mod", e);
            }

            try {
                fm = fm.clone();
            } catch (CloneNotSupportedException e) {
                log.error("Failure cloning flow mod", e);
            }
        }

        return srcSwitchIncluded;
    }   
    
    @Override
    public Command processPacketInMessage(IOFSwitch sw, OFPacketIn pi,
            IRoutingDecision decision, FloodlightContext cntx) {
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
                IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

        if (eth.isBroadcast() || eth.isMulticast()) {
            if (eth.getEtherType() == Ethernet.TYPE_ARP) {
                // retrieve arp to determine target IP address
                ARP arpRequest = (ARP) eth.getPayload();

                // check gw IP address, if false, bypass for normal handling
                boolean isExternal = (arpRequest.getTargetProtocolAddress()[0] != 10);

                if (isExternal) {
                    doProxyArp(sw, pi, cntx);
                 
                    //arp pushed already, bypass doFlood()
                    return Command.CONTINUE;
                }
            }

            // For now we treat multicast as broadcast
            doFlood(sw, pi, cntx);
        } else {

            MACAddress proxyArp = MACAddress.valueOf(GW_PROXY_ARP_MACADDRESS);
            MACAddress dstMac = MACAddress.valueOf(eth
                    .getDestinationMACAddress());

            if (proxyArp.equals(dstMac)) {
                cntx=prepInterDomainForwarding(cntx);
            }

            doForwardFlow(sw, pi, cntx, false);
        }

        return Command.CONTINUE;
    }

    // @Override
    // public Collection<Class<? extends IFloodlightService>>
    // getModuleServices() {
    // // TODO Auto-generated method stub
    // return null;
    // }
    //
    // @Override
    // public Map<Class<? extends IFloodlightService>, IFloodlightService>
    // getServiceImpls() {
    // // TODO Auto-generated method stub
    // return null;
    // }
    //
    // @Override
    // public Collection<Class<? extends IFloodlightService>>
    // getModuleDependencies() {
    // // TODO Auto-generated method stub
    // return null;
    // }
    //
    // @Override
    // public void init(FloodlightModuleContext context)
    // throws FloodlightModuleException {
    // // TODO Auto-generated method stub
    //
    // }
    //
    // @Override
    // public void startUp(FloodlightModuleContext context) {
    // // TODO Auto-generated method stub
    //
    // }

}

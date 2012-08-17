package net.floodlightcontroller.bgproute;

public class Rib {
	protected long prefix;
	protected short mask;
	protected short distance;
	
	Rib(long prefix, short mask) {
		this.prefix = prefix;
		this.mask = mask;
		this.distance = 100;
	}
}

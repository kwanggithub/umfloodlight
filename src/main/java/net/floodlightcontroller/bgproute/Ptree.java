package net.floodlightcontroller.bgproute;

import java.util.List;
import java.net.UnknownHostException;

public class Ptree {
	protected Ptree left;
	protected Ptree right;
	protected List<Rib> ribs;
	private Prefix prefix;
	int refCount;
	
	Ptree() {
		System.out.println("Ptree constructor");
		Prefix p = new Prefix("10.0.0.0", 24);
		refCount = 0;
		acquire(this, p);
	}
	
	public void acquire(Ptree tree, Prefix p) {
		Ptree match = null;
		Ptree node = this;
		
		if (prefix == null) {
			prefix = p;
			return;
		}
		
		while (node != null && node.prefix.masklen <= p.masklen) {
			
		}
		
	}
	
	public void addPrefix(Prefix p) {
		;
	}
	public void delPrefix(Prefix p) {
		;
	}
	
	public void getNode(Prefix p) {
		
	}

	public void lookupNode(Prefix p) {
		
	}

	public void addReference() {
		refCount++;
	}
	
	public void delReference() {
		refCount--;
	}
	
	public Ptree begin() {
		this.addReference();
		return this;
	}
	
	public Ptree next() {
		Ptree next;
		
		if (left != null) {
			next = left;
			next.addReference();
			this.delReference();
			return next;
		}
		return null;
	}
}

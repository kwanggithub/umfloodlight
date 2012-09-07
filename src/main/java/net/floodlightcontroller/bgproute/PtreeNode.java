package net.floodlightcontroller.bgproute;

public class PtreeNode {
	public PtreeNode parent;
	public PtreeNode left;
	public PtreeNode right;
	
	public byte key[];
	public int keyBits;
	
	public int refCount;
	
	public Rib rib;

	PtreeNode(byte [] key, int key_bits, int max_key_octet) {
		parent = null;
		left = null;
		right = null;
		refCount = 0;
		rib = null;
		this.key = new byte[max_key_octet];
		this.keyBits = key_bits;
		
		int octet = Ptree.bit_to_octet(key_bits);
		for (int i = 0; i < max_key_octet; i++) {
			if (i < octet) {
				if (key != null) {
					this.key[i] = key[i];
				}
			} else {
				this.key[i] = 0;
			}
		}
	}
}

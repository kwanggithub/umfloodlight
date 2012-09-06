package net.floodlightcontroller.bgproute;

public class PtreeNode {
	public PtreeNode parent;
	public PtreeNode left;
	public PtreeNode right;
	
	public int refCount;
	public int keyBits;
	public byte key[];
	
	PtreeNode(byte [] key, int key_bits, int max_key_octet) {
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

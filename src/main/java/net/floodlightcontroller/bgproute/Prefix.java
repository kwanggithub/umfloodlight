package net.floodlightcontroller.bgproute;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class Prefix {
	public int masklen;
	protected InetAddress address;
	
	Prefix(String str, int masklen) {
		try {
			address = InetAddress.getByName(str);
			System.out.println(address.toString());
		} catch (UnknownHostException e) {
			System.out.println("InetAddress exceptoin");
		}
		this.masklen = masklen;
		System.out.println(address.toString());
		System.out.println("mask ");
		System.out.println(masklen);
	}
}

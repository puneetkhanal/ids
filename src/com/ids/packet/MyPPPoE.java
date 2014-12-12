package com.ids.packet;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.packet.annotate.Field;

@Header(length = 8)
public class MyPPPoE extends JHeader {

	@Bind(to = Ethernet.class)
	public static boolean bindToEthernet(JPacket packet, Ethernet eth) {
		return eth.type() == 0x8864;
	}

	// @Bind(to = MyPPPoE.class, from = Ip4.class)
	// public static boolean bindIp4ToMyPPPoE(JPacket packet, MyPPPoE p) {
	//
	// System.out.printf("bindIp4ToMyPPPoE() nextId()==0x%X\n", p.nextId());
	// return p.nextId() == 0x21;
	// }

	@Field(offset = 0, length = 4)
	public int version() {
		return getUByte(0) & 0x0F;
	}

	@Field(offset = 4, length = 4)
	public int type() {
		return (getUByte(0) & 0xF0) >> 4;
	}

	@Field(offset = 1 * BYTE, length = 1 * BYTE)
	public int code() {
		return getUByte(1);
	}

	@Field(offset = 2 * BYTE, length = 2 * BYTE)
	public int sessionId() {
		return getUShort(2);
	}

	@Field(offset = 4 * BYTE, length = 2 * BYTE)
	public int length() {
		return getUShort(4);
	}

	@Field(offset = 6 * BYTE, length = 2 * BYTE, format = "%x")
	public int nextId() {
		return getUShort(6);
	}
}

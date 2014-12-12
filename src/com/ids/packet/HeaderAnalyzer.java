package com.ids.packet;

import java.nio.BufferUnderflowException;
import org.jnetpcap.packet.*;
import org.jnetpcap.packet.format.*;
import smile.Network;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import java.util.*;

import org.jnetpcap.protocol.lan.Ethernet;

import com.ids.bayes.Infer;
import com.ids.entities.ListData;

public class HeaderAnalyzer {
	private String ipinfo = null;
	private String tcpinfo = null;
	private String udpinfo = null;
	private String icmpinfo = null;
	private String frameinfo = null;
	private String ethernetinfo = null;
	private String myppoeinfo = null;
	private String typeinfo = null;
	private ListData tmp;
	private String s;
	private String s1;
	private String info;
	private String info1;
	private String[] strarr;
	private String[] srcdes;
	private String space;
	private String inferencevalue;
	private int tcpflag;
	private int udpflag;
	private boolean ackflag;
	private int icmptype;
	private int icmpcode;
	private int dstport;
	private int firsttimeflag;
	public static int firsttimetcp = 0;
	private int icmpflag;
	private String type;

	public HeaderAnalyzer() {

		tcpflag = 0;
		udpflag = 0;
		icmpflag = 0;
		s = null;
		s1 = null;
		info = null;
		info1 = null;
		space = "        ";
		strarr = new String[20];
		srcdes = new String[4];
		inferencevalue = null;
		firsttimeflag = 0;
		type = null;
		ackflag = true;

		tmp = new ListData();
	}

	public String getframeinfo() {
		return frameinfo;
	}

	public String getethernetinfo() {
		return ethernetinfo;
	}

	public String getipinfo() {
		return ipinfo;
	}

	public String gettcpinfo() {
		return tcpinfo;
	}

	public String getmyppoeinfo() {
		return myppoeinfo;
	}

	public String getudpinfo() {
		return udpinfo;
	}

	public String geticmpinfo() {
		return icmpinfo;
	}

	public void analyze(JPacket packet) {
		Ip4 ip = new Ip4();
		Icmp icmp = new Icmp();
		Tcp tcp = new Tcp();
		Udp udp = new Udp();
		Network net1 = new Network();
		Discrete po = new Discrete();
		Infer inf = new Infer();
		String state;
		int spp = 0;

		MyPPPoE my1 = new MyPPPoE();
		Ethernet eth = new Ethernet();

		frameinfo = ":"
				+ new Date(packet.getCaptureHeader().timestampInMillis())
				+ "\n";
		frameinfo += ":" + packet.getCaptureHeader().caplen() + "  bytes"
				+ "\n";
		frameinfo += ":" + packet.getCaptureHeader().wirelen() + "  bytes"
				+ "\n";

		if (packet.hasHeader(eth)) {

			ethernetinfo = ":" + FormatUtils.mac(eth.source()) + "\n";
			ethernetinfo += ":" + FormatUtils.mac(eth.destination()) + "\n";
			ethernetinfo += ":" + eth.type();

		}

		if (packet.hasHeader(my1)) {

			myppoeinfo = ":" + my1.version() + "\n";
			myppoeinfo += ":" + my1.type() + "\n";
			myppoeinfo += ":" + my1.sessionId() + "\n";
			myppoeinfo += ":" + my1.length() + "\n";
			myppoeinfo += ":" + my1.nextId();
		}

		if (packet.hasHeader(ip)) {
			// System.out.println();

			ipinfo = ":" + ip.version() + "\n";
			ipinfo += ":" + FormatUtils.ip(ip.source()) + "\n";

			ipinfo += ":" + FormatUtils.ip(ip.destination()) + "\n";

			ipinfo += ":" + ip.hlen() * 4 + "  bytes" + "\n";

			if (ip.isChecksumValid() == true)
				state = "Correct";
			else
				state = "Incorrect";

			ipinfo += ":" + ip.checksum() + "  [" + state + "]" + "\n";

			ipinfo += ":" + ip.type() + "\n";

			ipinfo += ":" + ip.length() + "\n";

			ipinfo += ":" + ip.ttl() + "\n";

			ipinfo += ":" + ip.flags_DF() + "\n";

			ipinfo += ":" + ip.flags_MF() + "\n";

			ipinfo += ":" + ip.offset();

		}

		if (packet.hasHeader(tcp)) {

			// if(firsttimetcp==1)

			tcpinfo = ":" + tcp.source() + "\n";

			tcpinfo += ":" + tcp.destination() + "\n";
			tcpinfo += ":" + tcp.urgent() + "\n";
			tcpinfo += ":" + tcp.ack() + "\n";
			tcpinfo += ":" + tcp.seq() + "\n";

			try {
				if (tcp.isChecksumValid() == true)
					state = "Correct";
				else
					state = "Incorrect";

			} catch (BufferUnderflowException e) {
				state = "null";
				// System.out.println("BufferUnderflowException");
			}

			tcpinfo += ":" + tcp.checksum() + "   [" + state + "]" + "\n\n";

			tcpinfo += ":" + tcp.flags_URG() + "\n";

			tcpinfo += ":" + tcp.flags_ACK() + "\n";

			tcpinfo += ":" + tcp.flags_PSH() + "\n";

			tcpinfo += ":" + tcp.flags_RST() + "\n";

			tcpinfo += ":" + tcp.flags_SYN() + "\n";

			tcpinfo += ":" + tcp.flags_FIN() + "\n";

			tcpinfo += ":" + tcp.window();

		}

		if (packet.hasHeader(udp)) {

			udpinfo = ":" + udp.source() + "\n";
			udpinfo += ":" + udp.destination() + "\n";

			try {
				if (udp.isChecksumValid() == true)
					state = "Correct";
				else
					state = "Incorrect";

			} catch (BufferUnderflowException e) {
				state = "null";
				// System.out.println("BufferUnderflowException");
			}

			udpinfo += ":" + udp.checksum() + "   [" + state + "]" + "\n";
			udpinfo += ":" + udp.length() + "\n";

		}

		if (packet.hasHeader(icmp)) {

			icmpinfo = ":" + icmp.type() + "(" + icmp.typeDescription() + ")"
					+ "\n";
			icmpinfo += ":" + icmp.code() + "\n";

			try {
				if (icmp.isChecksumValid() == true)
					state = "Correct";
				else
					state = "Incorrect";

			} catch (BufferUnderflowException e) {
				state = "null";
			}

			icmpinfo += ":" + icmp.checksum() + "[" + state + "]" + "\n";

		}

	}

}
package com.ids.packet;

public class Discrete {
	public String flag(boolean value) {
		if (value == true)
			return "1";
		else
			return "0";
	}

	public String tostring(int i) {
		String s = new Integer(i).toString();
		return s;
	}

	public String iplength(int length) {
		String len;

		if (length < 28)
			len = "less_28";
		else if (length == 28)
			len = "28";
		else if (length > 28 && length < 50)
			len = "28_50";
		else if (length == 50)
			len = "50";
		else if (length > 50 && length <= 150)
			len = "50_150";
		else if (length > 150 && length < 1052)
			len = "150_1052";
		else if (length == 1052)
			len = "1052";
		else if (length > 1052 && length < 1500)
			len = "1052_1500";
		else if (length == 1500)
			len = "1500";
		else
			len = "above1500";

		return len;
	}

	public String caplen(int i) {
		String cap;

		if (i < 1000)
			cap = "below_1000";
		else
			cap = "ablove_1000";

		return cap;
	}

	public String ttl(int i) {
		String s;

		if (i < 64) {
			s = "TTL1";

		} else if (i > 64 && i <= 128) {
			s = "TTL2";

		} else if (i > 128 && i <= 192) {
			s = "TTL3";

		} else if (i > 192 && i <= 255) {
			s = "TTL4";

		} else {
			s = "TTL5";
		}

		return s;
	}

	public String windowsize(int s) {
		String size;
		// size="State_"+s;

		if (s == 0)
			size = "0";
		else if (s > 0 && s < 242)
			size = "0_242";
		else if (s == 242)
			size = "242";
		else if (s > 242 && s < 512)
			size = "242_512";
		else if (s == 512)
			size = "512";
		else
			size = "above512";

		return size;
	}

	public String offset(int i) {
		String off;

		if (i == 0) {

			off = "0";

		} else
			off = "1";

		return off;
	}

	public String port(int src) {
		String source;

		if (src < 21) {
			source = "less21";

		} else if (src == 20) {
			source = "ftp_data";

		} else if (src == 21) {
			source = "ftpcontrol";

		} else if (src == 22) {
			source = "ssh";

		} else if (src == 23) {
			source = "telnet";

		} else if (src == 25) {
			source = "smtp";

		} else if (src > 25 && src < 53) {
			source = "25_53";

		} else if (src == 53) {
			source = "dns";

		} else if (src > 53 && src < 79) {
			source = "53_79";

		} else if (src == 79) {
			source = "finger";

		} else if (src == 80) {
			source = "http";

		} else if (src > 80 && src < 161) {
			source = "80_161";

		} else if (src == 161) {
			source = "snmp";

		} else if (src > 161 && src < 1234) {
			source = "161_1234";

		} else if (src == 1234) {
			source = "search-agent";

		} else if (src > 1234 && src < 49724) {
			source = "1234_49724";

		} else if (src == 49724) {
			source = "49724";

		} else
			source = "above49724";

		return source;
	}

}
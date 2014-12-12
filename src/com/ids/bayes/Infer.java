package com.ids.bayes;

public class Infer {
	public String flag(boolean value) {
		if (value == true)
			return "State_1";
		else
			return "State_0";
	}

	public String type(int i) {
		if (i == 6)
			return "State_6";
		else if (i == 1)
			return "State_1";
		else
			return "State_17";
	}

	public String domore(int i) {
		if (i == 0)
			return "State_0";
		else
			return "State_1";
	}

	public String iplength(int length) {
		String len;

		if (length < 28)
			len = "less_28";
		else if (length == 28)
			len = "State_28";
		else if (length > 28 && length < 50)
			len = "State_28_50";
		else if (length == 50)
			len = "State_50";
		else if (length > 50 && length <= 150)
			len = "State_50_150";
		else if (length > 150 && length < 1052)
			len = "State_150_1052";
		else if (length == 1052)
			len = "State_1052";
		else if (length > 1052 && length < 1500)
			len = "State_1052_1500";
		else if (length == 1500)
			len = "State_1500";
		else
			len = "State_above1500";

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
		s = "State_" + i;
		/*
		 * if(i<64) { s="TTL1"; } else if(i>64&&i<=128) { s="TTL2"; } else
		 * if(i>128&&i<=192) { s="TTL3"; } else if(i>192&&i<=255) { s="TTL4";
		 * 
		 * } else { s="TTL5"; }
		 */
		return s;
	}

	public String windowsize(int s) {
		String size;
		size = "State_" + s;

		if (s == 0)
			size = "State_0";
		else if (s > 0 && s < 242)
			size = "State_0_242";
		else if (s == 242)
			size = "State_242";
		else if (s > 242 && s < 512)
			size = "State_242_512";
		else if (s == 512)
			size = "State_512";
		else
			size = "above512";

		return size;
	}

	public String offset(int i) {
		String off;

		if (i == 0) {

			off = "State_0";

		} else

			off = "State_1";

		return off;
	}

	public String tostring(int i) {
		String s = new Integer(i).toString();
		s = "State_" + s;
		return s;
	}

	public String port(int src) {
		String source;
		// if(src<21)
		// {
		// source="State_21";
		// }

		if (src == 20) {
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
			source = "State_25_53";

		} else if (src == 53) {
			source = "dns";

		} else if (src > 53 && src < 79) {
			source = "State_53_79";

		} else if (src == 79) {
			source = "finger";

		} else if (src == 80) {
			source = "http";

		} else if (src > 80 && src < 161) {
			source = "State_80_161";

		} else if (src == 161) {
			source = "snmp";

		} else if (src > 161 && src < 1234) {
			source = "State_161_1234";

		} else if (src == 1234) {
			source = "search-agent";

		} else if (src > 1234 && src < 49724) {
			source = "State_1234_49724";

		} else if (src == 49724) {
			source = "State_49724";

		} else
			source = "State_above49724";

		return source;
	}

}
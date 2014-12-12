package com.ids.entities;

import javax.swing.DefaultListModel;


public class UpdateList {
	private DefaultListModel ljep;

	public UpdateList(DefaultListModel ljp) {
		ljep = ljp;
	}

	public void add(int i, String s1, String info, String s, String t,
			String frame, String ethernet, String myppoe, String ip,
			String tcp, String udp, String icmp, String packettype) {
		ListData tmp;
		tmp = new ListData();
		tmp.data = info;
		tmp.header = s1;
		tmp.dataset = s;
		tmp.type = t;
		tmp.ip = ip;
		tmp.tcp = tcp;
		tmp.ethernet = ethernet;
		tmp.frame = frame;
		tmp.myppoe = myppoe;
		tmp.udp = udp;
		tmp.icmp = icmp;
		tmp.packettype = packettype;
		// System.out.println(i+info);
		ljep.add(i, tmp);
	}

}
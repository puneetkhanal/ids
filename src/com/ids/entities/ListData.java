package com.ids.entities;

public class ListData {
	public String header;
	public String data;
	public String dataset;
	public String type;
	public String ip;
	public String tcp;
	public String ethernet;
	public String frame;
	public String myppoe;
	public String udp;
	public String icmp;
	public String packettype;

	@Override
	public String toString() {
		return header;
	}

}
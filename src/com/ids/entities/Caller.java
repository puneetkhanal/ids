package com.ids.entities;

import java.util.Vector;
import org.jnetpcap.util.PcapPacketArrayList;


public class Caller {
	public int threadResult;
	public PcapPacketArrayList array;
	public Vector vector;
	public Vector analomous;
	// later, in some method, create a result setter:
	public ResultSetter setter = new ResultSetter() {

		@Override
		public void setResult(Vector result, Vector ana) {
			array = new PcapPacketArrayList();
			vector = new Vector();
			vector = result;
			analomous = new Vector();
			analomous = ana;
		}
	};
}
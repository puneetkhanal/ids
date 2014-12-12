package com.ids.packet;

import java.util.logging.Level;
import java.util.logging.Logger;
import org.jnetpcap.*;
import org.jnetpcap.packet.*;
import org.jnetpcap.protocol.network.Ip4;

import com.ids.MainGui;
import com.ids.entities.ListData;
import com.ids.entities.ResultSetter;
import com.ids.entities.UpdateList;
import com.ids.utils.FileWrite;

import java.awt.Color;
import java.awt.Component;
import java.text.*;
import javax.swing.*;
import java.util.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;

//Class that implements the background thread in which the sniffing is done.

public class SnifferThread extends Thread {
	private ResultSetter setter;
	private MainGui frame;
	private String ldevice;
	private DefaultListModel ljep;
	private DefaultTableModel table;
	private DefaultTableModel table1;
	private JTextArea aa;
	private String ofile;
	private int noofattack;
	private Pcap pcap;
	private PcapDumper dumper;
	private int number;
	private int attacktype;
	private int flag;
	private FileWrite f;
	private int count;
	private int noofpackets;
	private int counter;
	private JPacket pac;
	private JTable tablem;
	private JTable tablem1;
	private boolean anamode;
	private int dumperflag;
	private String s;
	private String s1;
	private String info;
	private String[] strarr;
	private String[] srcdes;
	private String space;
	private int tcpflag;
	private int udpflag;
	private boolean ackflag;
	private int icmptype;
	private int packetnumber = 0;
	public static int firsttimetcp = 0;
	private int icmpflag;
	private String atype;
	private Vector vector;
	private Vector analomous;
	private JTextArea attacknumber;
	private boolean monitor;
	private int numb;
	private int newfilecounter;

	public SnifferThread(String device, boolean type, int i, int j,
			JTextArea a, DefaultTableModel tt, DefaultTableModel ttt,
			DefaultListModel jep, JTable tab, JTable tab1, MainGui frm,
			boolean mon, boolean log, JTextArea jt, int file) {
		ldevice = device;
		ljep = jep;
		number = i;
		numb = file;
		frame = frm;
		attacktype = j;
		aa = a;
		attacknumber = jt;
		noofpackets = -1;
		table = tt;
		table1 = ttt;
		counter = 0;
		flag = 0;
		tablem = tab;
		tablem1 = tab1;
		dumperflag = 0;
		anamode = log;
		noofattack = 0;
		monitor = mon;
		vector = new Vector();
		analomous = new Vector();

		f = new FileWrite();
	}

	public void setResultSetter(ResultSetter setter) {
		this.setter = setter;
	}

	/*
	 * Kills the infinite loop that the pcap library goes into while sniffing
	 * packets. I declare this method syncronized to force java to treat it as a
	 * critical section (forces only one thread at a time to be able to access
	 * it).
	 */

	public synchronized void stopthread() {
		if (noofpackets == -1) {

			pcap.breakloop();
		}
	}

	/* The threads run method (where all the action happens). */
	@Override
	public void run() {
		// First get a list of devices on this system

		try {
			List<PcapIf> alldevs = new ArrayList<PcapIf>();
			StringBuilder errbuf = new StringBuilder();
			// First get a list of devices on this system
			int r = Pcap.findAllDevs(alldevs, errbuf);

			if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
				System.err.printf("Can't read list of devices, error is %s",
						errbuf.toString());
				return;
			}

			if (number >= 0) {
				PcapIf device = alldevs.get(number); // We know we have atleast
														// 1 device
				// System.out.printf("\nChoosing '%s' on your behalf:\n",
				// (device.getDescription() != null) ? device.getDescription() :
				// device.getName());
				// Second we open up the selected device
				int snaplen = 64 * 1024; // Capture all packets, no trucation
				// int flags = Pcap.MODE_PROMISCUOUS;
				int flags = Pcap.MODE_BLOCKING; // capture all packets
				int timeout = 10 * 1000; // 10 seconds in millis
				pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout,
						errbuf);
				// System.out.print(ldevice);

			} else {
				// System.out.println("number:"+number);
				String fname = ldevice;
				// System.out.print(ofile);
				pcap = Pcap.openOffline(fname, errbuf);

				if (pcap == null) {
					JOptionPane
							.showMessageDialog(
									frame,
									"Please select correct file format(.cap,.pcap,.tcpdump).",
									"Incorrect File Format",
									JOptionPane.ERROR_MESSAGE);
					return;
				}

				// dumper = pcap.dumpOpen(ofile);
			}

			PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

				@Override
				public void nextPacket(PcapPacket packet, String user) {
					String ipinfo = null;
					String tcpinfo = null;
					String udpinfo = null;
					String icmpinfo = null;
					String frameinfo = null;
					String ethernetinfo = null;
					String myppoeinfo = null;
					String typeinfo = null;
					String state = null;
					String[] arr;
					arr = new String[25];

					if (flag == 0) {
						pac = packet;
						flag = 1;

					}

					pac = packet; // exchange

					if (anamode == true && monitor == true && s1 != null) {

						arr = strarr;

						arr[19] = count + "";

						table.insertRow(0, new Object[] { arr[19], arr[0],
								arr[1], arr[2], arr[3], arr[4], arr[5], arr[6],
								arr[7], arr[8], arr[9], arr[10], arr[11],
								arr[12], arr[13], arr[14], arr[15], arr[16],
								arr[17], arr[18] }

						);
						// DefaultTableCellRenderer headerRenderer = new
						// DefaultTableCellRenderer();
						tablem.setDefaultRenderer(Object.class, new MyRenderer(
								19));

						if (atype == "attack") {
							noofattack++;

							if (newfilecounter == 0) {
								DateFormat dateFormat = new SimpleDateFormat(
										"yyyy-MM-dd,HH-mm-ss");
								java.util.Date date = new java.util.Date();
								String datetime = dateFormat.format(date);
								// System.out.println("Current Date Time : " +
								// datetime);
								ofile = datetime + ".cap";

								if (dumper != null)
									dumper.close();

								dumper = pcap.dumpOpen(ofile);

								PcapHeader header = new PcapHeader(
										packet.size(), packet.size());

								dumper.dump(header, packet);

								newfilecounter++;

							} else {
								PcapHeader header = new PcapHeader(
										packet.size(), packet.size());
								dumper.dump(header, packet);
								newfilecounter++;

								if (newfilecounter > 20000)
									newfilecounter = 0;
							}
						}

						count = count + 1;
					}

					if (noofattack == 0)
						attacknumber.setForeground(Color.black);
					else
						attacknumber.setForeground(Color.red);

					attacknumber.setText("Number of anomalous packets:    "
							+ noofattack);

					// table.addRow(new
					// Object[]{arr[0],arr[1],arr[2],arr[3],arr[4],arr[5],arr[6],arr[7],arr[8],arr[9],arr[10],arr[11],arr[12],arr[13],arr[14],arr[15],arr[16],arr[17]});
					if (s1 != null && monitor == false) {
						// System.out.println(strarr[16]+":"+strarr[0]);
						// array.add(count, pac);
						String[] varray = new String[13];
						varray[0] = count + "";
						varray[1] = srcdes[0];
						varray[2] = srcdes[1];
						varray[3] = atype;
						varray[4] = info;
						varray[5] = frameinfo;
						varray[6] = ethernetinfo;
						varray[7] = myppoeinfo;
						varray[8] = ipinfo;
						varray[9] = tcpinfo;
						varray[10] = udpinfo;
						varray[11] = icmpinfo;
						varray[12] = typeinfo;

						if (atype == "attack") {
							noofattack++;
							// JOptionPane.showMessageDialog(frame,
							// "Attack Detected",
							// "Number of analomous packets:",
							// JOptionPane.ERROR_MESSAGE);
							analomous.add(varray);
						}

						// attacknumber.setBackground(Color.green);

						vector.add(varray);

						arr = strarr;

						arr[19] = count + "";

						table.insertRow(0, new Object[] { arr[19], arr[0],
								arr[1], arr[2], arr[3], arr[4], arr[5], arr[6],
								arr[7], arr[8], arr[9], arr[10], arr[11],
								arr[12], arr[13], arr[14], arr[15], arr[16],
								arr[17], arr[18] }

						);
						// DefaultTableCellRenderer headerRenderer = new
						// DefaultTableCellRenderer();
						tablem.setDefaultRenderer(Object.class, new MyRenderer(
								19));
						UpdateList l = new UpdateList(ljep);

						if (count <= 19) {
							l.add(count, s1, info, s, atype, frameinfo,
									ethernetinfo, myppoeinfo, ipinfo, tcpinfo,
									udpinfo, icmpinfo, typeinfo);
							String[] arr1;
							arr1 = new String[4];
							arr1 = srcdes;
							arr1[3] = count + "";
							table1.insertRow(count, new Object[] { arr1[3],
									arr1[0], arr1[1], arr1[2] });
							tablem1.setDefaultRenderer(Object.class,
									new MyRender(3));

						}

						ListData tmp;

						tmp = new ListData();

						if (attacktype == 0) {
							s += "normal";
						}

						if (attacktype == 1) {
							s += "attack";
						}

						try {
							// devices = JpcapCaptor.getDeviceList();
							// Thread.sleep(5);//jpcap =
							// JpcapCaptor.openDevice(devices[ldevice], 2000,
							// false, 20);
							// jpcap.loopPacket(-1,new Sniffer(ljep,type));

						} catch (Exception ex) {
							ex.printStackTrace();
						}

						if (numb == 4) {
							if (count == 0) {
								f.write("protocol\tiplength\tttl\tdf\tmf\toffset\tsynflood\turgent\tack\tpsh\trst\tsyn\tfin\twinsize\ticmpflood\ticmpchecksum\ttype",
										100, false);
							}

							f.write(s, 100, true);
						}

						if (numb == 3) {
							f.write(s, 100, true);
						} // System.out.println(info1);

						setter.setResult(vector, analomous);

						// tmp.ttl=Integer.toString(ip.length());
						count = count + 1;

						counter++;
					}

					// flag=0;
				}
			};

			final int myId = JRegistry.register(MyPPPoE.class);
			JRegistry
					.addBindings(new JBinding[] { new JBinding.DefaultJBinding(
							Ip4.ID, myId) {

						@Override
						public int getSourceId() {
							return getId();
						}

						private final MyPPPoE my = new MyPPPoE();

						@Override
						public boolean isBound(JPacket packet, int offset) {
							return packet.hasHeader(my) && my.nextId() == 0x21;
						}
					} });
			pcap.loop(noofpackets, jpacketHandler, "jNetPcap rocks!");
			// tem.out.printf("%s file has %d bytes in it!\n", ofile,
			// file.length());

		} catch (RegistryHeaderErrors ex) {
			Logger.getLogger(SnifferThread.class.getName()).log(Level.SEVERE,
					null, ex);
		}

		// System.out.print("count"+count+":"+array.size());

		/*
		 * tmp=(listdata)ljep.get(1); System.out.println(tmp.data);
		 * tmp=(listdata)ljep.get(0); System.out.println(tmp.data);
		 */
		// System.out.println("Protocol"+space+"IPLength"+space+"TTL"+space+"DF"+space+"MF"+space+"Offset"+space+"SrcPort"+space+"DstPort"+space+"URG"+space+"ACK"+space+"PSH"+space+"RST"+space+"SYN"+space+"FIN"+space+"WinSize"+space+"IcmpCode"+space+"IcmpType");
		// aa.insert("Protocol"+space+"IPLength"+space+"TTL"+space+"DF"+space+"MF"+space+"Offset"+space+"SrcPort"+space+"DstPort"+space+"URG"+space+"ACK"+space+"PSH"+space+"RST"+space+"SYN"+space+"FIN"+space+"WinSize"+space+"IcmpCode"+space+"IcmpType",0);
		// aa.insert("Protocol    IPLength    TTL    DF    MF    Offset    SrcPort    DstPort    URG    ACK    PSH    RST    SYN    FIN    WinSize    IcmpCode    IcmpType",0)
		// ;
		// aa.insert("PACKET CAPTURED:", 0);
		// System.out.println("Protocol    IPLength    TTL    DF    MF    Offset    SrcPort    DstPort    URG    ACK    PSH    RST    SYN    FIN    WinSize    IcmpCode    IcmpType")
		// ;pcap.close();

	}

}

class MyRender extends DefaultTableCellRenderer {
	private int coll;

	public MyRender(int j) {

		coll = j;
	}

	@Override
	public Component getTableCellRendererComponent(JTable table, Object value,
			boolean isSelected, boolean hasFocus, int row, int col) {
		Component comp1 = super.getTableCellRendererComponent(table, value,
				isSelected, hasFocus, row, col);

		String s = table.getModel().getValueAt(row, coll).toString();
		// System.out.println(s);
		// System.out.println(roww+":"+coll+str);

		if (s == "normal") {

			comp1.setBackground(Color.white);
			comp1.setForeground(Color.black);
			// comp1.setForeground(Color.black);

		}

		if (s == "attack") {
			comp1.setBackground(Color.black);
			comp1.setForeground(Color.white);
			// comp1.setForeground(Color.red);

		}

		return (comp1);
	}
}

class MyRenderer extends DefaultTableCellRenderer {
	private int column;

	public MyRenderer(int j) {
		column = j;
	}

	@Override
	public Component getTableCellRendererComponent(JTable table, Object value,
			boolean isSelected, boolean hasFocus, int row, int col) {
		Component comp = super.getTableCellRendererComponent(table, value,
				isSelected, hasFocus, row, col);

		String s = table.getModel().getValueAt(row, column).toString();
		// System.out.println(row+":"+col);

		if (s == "normal") {
			comp.setBackground(Color.white);
			comp.setForeground(Color.black);
			// comp.setForeground(Color.black);

		} else {
			comp.setBackground(Color.black);
			comp.setForeground(Color.white);
			// comp.setForeground(Color.red);

		}

		return (comp);
	}
}
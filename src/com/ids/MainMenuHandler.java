package com.ids;

import javax.swing.event.*;
import org.jnetpcap.*;
import java.util.List;
import java.io.*;
import org.jnetpcap.packet.*;

import com.ids.bayes.Naivebayes;
import com.ids.dialog.AboutDialog;
import com.ids.entities.Caller;
import com.ids.entities.ListData;
import com.ids.entities.UpdateList;
import com.ids.filter.LogFilter;
import com.ids.packet.SnifferThread;
import com.ids.utils.FileWrite;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import java.util.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeSelectionModel;

public class MainMenuHandler implements MouseListener, ListSelectionListener,
		ActionListener, KeyListener, TreeSelectionListener {
	private UIManager.LookAndFeelInfo[] landf;
	private FileWrite f;
	private DefaultListModel ljp;
	private DefaultTableModel table;
	private MainGui frame;
	private JMenuBar menubar;
	private JMenu landfmenu;
	private JMenu sniffermenu;
	private JMenu aboutmenu;
	private JMenu datasetmenu;
	private JPopupMenu popup;
	private int threadResult;
	private int count;
	private int flag;
	String s;
	private int startingvalue = 20;
	private JButton okButton;
	JRadioButton wholeCheck, headCheck, userCheck;
	private int nextflag = 1;
	private int analomous = 0;
	private int anaflag = 0;
	private int normalflag = 0;
	private int firsttimeflag = 0;
	ListData tmp;

	// private ResultSetter ss;
	public int getanalomous() {
		return analomous;
	}

	public void next(int option) {

		int remove;

		int iii;

		// System.out.println("Success"+nnn.array.size()+":"+count);
		Vector vector = new Vector();

		if (firsttimeflag == 0) {
			vector = nnn.vector;
			count = 20;
			firsttimeflag = 1;

		} else {
			if (option == 0) {
				vector = nnn.vector;

				if (normalflag == 0)
					count = 0;

				normalflag = 1;
			}

			if (option == 1) {

				vector = nnn.analomous;

				if (anaflag == 0)
					count = 0;

				anaflag = 1;
			}
		}

		if (count > vector.size() - 1) {
			JOptionPane.showMessageDialog(frame,
					"Click Previous to view packets.",
					"Reached end of the list", JOptionPane.ERROR_MESSAGE);
			return;
		}

		if ((count / 10) % 2 == 0)
			iii = count % 10;
		else
			iii = 10 + count % 10;

		if (iii == 0) {
			iii = 20;
		}

		// iii=20;
		remove = ljp.size();

		startingvalue = iii;

		String s = null;

		String s1 = null;

		String info = null;

		ljp.clear();

		UpdateList l = new UpdateList(getModel());

		while (remove > 0) {

			// System.out.println(table.getRowCount());

			table.removeRow(remove - 1);

			remove--;
		}

		for (int j = 0; j < startingvalue; j++) {

			String[] varray = new String[4];

			if (count > vector.size() - 1) {
				// JOptionPane.showMessageDialog(frame,
				// "Click Previous to view packets.", "Reached end of the list",
				// JOptionPane.ERROR_MESSAGE);
				return;
			}

			varray = (String[]) vector.get(count);
			l.add(j, varray[0], varray[4], varray[2], varray[3], varray[5],
					varray[6], varray[7], varray[8], varray[9], varray[10],
					varray[11], varray[12]);

			table.insertRow(j, new Object[] { varray[0], varray[1], varray[2],
					varray[3] });
			gettable2().setDefaultRenderer(Object.class, new MyRende(3));
			count++;

		}

	}

	public void previous(int option) {

		int remove;

		int iii;

		Vector vector = new Vector();

		if (option == 0)
			vector = nnn.vector;

		if (option == 1) {
			// System.out.println(nnn.analomous.size());
			vector = nnn.analomous;

		}

		if (vector == null) {
			JOptionPane.showMessageDialog(frame,
					"Start capturing from Packet Sniffing menu.",
					"Packets not captured yet", JOptionPane.ERROR_MESSAGE);
			return;
		}

		if ((vector.size()) == count) // for packets not equal to sum of 20
		{

			if ((count / 10) % 2 == 0)
				iii = count % 10;
			else
				iii = 10 + count % 10;

			if (iii == 0) {
				iii = 20;
			}

		} else {
			iii = 20;

		}

		// remove=iii;
		remove = ljp.size();

		startingvalue = 20;

		count = count - iii - 20;

		if (count < 0) {
			count += 40;
			JOptionPane.showMessageDialog(frame, "Click Next to view packets.",
					"Reached start of the list", JOptionPane.ERROR_MESSAGE);

			return;
		}

		PcapPacket packet;

		String s = null;
		String s1 = null;
		String info = null;

		ljp.clear();

		UpdateList l = new UpdateList(getModel());

		while (remove > 0) {

			table.removeRow(remove - 1);

			remove--;
		}

		for (int j = 0; j < startingvalue; j++) {

			String[] varray = new String[4];
			varray = (String[]) vector.get(count);

			l.add(j, varray[0], varray[4], varray[2], varray[3], varray[5],
					varray[6], varray[7], varray[8], varray[9], varray[10],
					varray[11], varray[12]);

			table.insertRow(j, new Object[] { varray[0], varray[1], varray[2],
					varray[3] });
			gettable2().setDefaultRenderer(Object.class, new MyRende(3));

			count++;

		}
	}

	public void fromfile(int num, int val) {
		FileOutputStream out = null;
		int sz = 0;
		ListData lst = null;
		String dst = null;
		JFileChooser fs = null;
		File tmpfl = null;
		File selectedFile = null;
		String strtmp = null;
		String savdir = null;
		AboutDialog ad = null;
		SnifferThread tmpthrd = null;
		count = startingvalue; // for next capture
		/*
		 * if(frame.getType()==-1) { JOptionPane.showMessageDialog(frame,
		 * "Please select a network interface.",
		 * "No Network Interface Selected", JOptionPane.ERROR_MESSAGE); return;
		 * }
		 */

		// frame.getTextArea2().updateUI();
		// frame.getTextArea1().setText("");

		if (frame.getsniffer() != null) {
			frame.getsniffer().stopthread();
			frame.setsniffer(null);
		}

		// System.out.print(getType1()+"ss");
		fs = new JFileChooser();

		// fs.addChoosableFileFilter(new LogFilter(".cap"));
		// fs.addChoosableFileFilter(new LogFilter(".pcap"));
		fs.setAlignmentX(frame.getAlignmentX());

		fs.setAlignmentY(frame.getAlignmentY());

		fs.setSelectedFile(null);

		if (fs.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
			savdir = fs.getCurrentDirectory().toString();
			tmpfl = fs.getSelectedFile();

			if (tmpfl != null) {
				strtmp = tmpfl.toString();
				// System.out.println(strtmp);

				if (strtmp.indexOf('.') > 0) {
					// strtmp=strtmp.substring(0,strtmp.lastIndexOf('.'));
					// System.out.print(strtmp);
				}

				/*
				 * selectedFile = new File(strtmp +
				 * fs.getFileFilter().getDescription()); try {
				 * if(selectedFile!=null) { try { /*out = new
				 * FileOutputStream(selectedFile); PrintStream p; for(int
				 * i=0;i<sz;i++) { lst=(listdata)frame.getModel().get(i); //dst
				 * = lst.header + "\r\n" + lst.data +
				 * "\r\n\r\n---------------------------------\r\n\r\n"; p = new
				 * PrintStream( out ); dst =
				 * lst.data;//out.write(dst.getBytes(),0,dst.length());
				 * p.print(dst+"\r\n"); } out.close();
				 * //frame.getModel().removeAllElements();
				 * //frame.getTextArea1().setText(""); } catch(Exception errr) {
				 * System.out.println(errr.toString()); } } catch(Exception err)
				 * { System.out.println(err.toString()); }
				 */
			}
		}

		if (table.getRowCount() > 0) {

			int remove = ljp.size();

			// System.out.println("\nremove:"+remove);
			while (remove > 0) {

				table.removeRow(remove - 1);

				remove--;
			}
		}

		getModel().clear();
		String s;

		if (strtmp == null) {
			JOptionPane.showMessageDialog(frame, "Please select a file.",
					"No file Selected", JOptionPane.ERROR_MESSAGE);
			return;
		}

		// System.out.println("filename"+strtmp);
		tmpthrd = new SnifferThread(strtmp, false, -1, val, getTextArea1(),
				getModel1(), getModel2(), getModel(), gettablle(), gettable2(),
				frame, false, false, jt, num);

		frame.setsniffer(tmpthrd);

		tmpthrd.setResultSetter(nnn.setter);

		// System.out.println("hiiiiiiiiiiiii"+ss);
		tmpthrd.start();
	}

	public void fromdevice(int type, boolean monitor, boolean logging) {
		FileOutputStream out = null;
		int sz = 0;
		ListData lst = null;
		String dst = null;
		JFileChooser fs = null;
		File tmpfl = null;
		File selectedFile = null;
		String strtmp = null;
		String savdir = null;
		AboutDialog ad = null;
		SnifferThread tmpthrd = null;
		count = startingvalue; // for next capture

		if (type == -1) {
			JOptionPane.showMessageDialog(frame,
					"Please select a network interface.",
					"No Network Interface Selected", JOptionPane.ERROR_MESSAGE);
			return;
		}

		// getTextArea2().updateUI();
		// getTextArea1().setText("");
		if (frame.getsniffer() != null) {
			frame.getsniffer().stopthread();
			frame.setsniffer(null);
		}

		String s;
		s = Integer.toString(frame.getType());
		tmpthrd = new SnifferThread(s, true, type, frame.getType1(), jt3,
				getModel1(), getModel2(), getModel(), gettablle(), gettable2(),
				frame, monitor, logging, jt, -1);

		if (monitor == true) {
			jt1.setForeground(Color.black);
			jt1.setText("Monitoring Mode is on.\n\nIn this mode, analomous packet is dumped if logging mode is on. The dumped file can later be analyzed.");
		}

		frame.setsniffer(tmpthrd);
		tmpthrd.setResultSetter(nnn.setter);

		if (table.getRowCount() > 0) {

			int remove = ljp.size();

			// System.out.println("\nremove:"+remove);
			while (remove > 0) {

				table.removeRow(remove - 1);

				remove--;
			}
		}

		getModel().clear();
		tmpthrd.start();
	}

	public void learn() {
		FileOutputStream out = null;
		int sz = 0;
		ListData lst = null;
		String dst = null;
		JFileChooser fs = null;
		File tmpfl = null;
		File selectedFile = null;
		String strtmp = null;
		String savdir = null;
		AboutDialog ad = null;
		SnifferThread tmpthrd = null;
		Naivebayes bayes = new Naivebayes();
		fs = new JFileChooser();
		fs.addChoosableFileFilter(new LogFilter(".txt"));

		fs.setAlignmentX(frame.getAlignmentX());
		fs.setAlignmentY(frame.getAlignmentY());
		fs.setSelectedFile(null);

		if (fs.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
			savdir = fs.getCurrentDirectory().toString();
			tmpfl = fs.getSelectedFile();

			if (tmpfl != null) {
				strtmp = tmpfl.toString();
				// System.out.println(strtmp);

				if (strtmp.indexOf('.') > 0) {
					// strtmp=strtmp.substring(0,strtmp.lastIndexOf('.'));
					// System.out.print(strtmp);
				}
			}

			// System.out.print(strtmp);

		}

		if (strtmp == null) {
			JOptionPane.showMessageDialog(frame, "Please select a file.",
					"No file Selected", JOptionPane.ERROR_MESSAGE);
			return;
		}

		bayes.learn(strtmp);

		JOptionPane.showMessageDialog(frame, "Naive Bayes Learning completed.",
				"Success", JOptionPane.INFORMATION_MESSAGE);

	}

	public void selectpacket() {
		ListData lst = null;
		String dst = null;
		int j = getselect();
		// System.out.println("Select"+j);

		if (j == 0) {
			JOptionPane
					.showMessageDialog(
							frame,
							"Start capturing from packet sniffing menu and select packet",
							"Packet not selected", JOptionPane.ERROR_MESSAGE);
			return;
		}

		/*
		 * if(frame.getsniffer()!=null) { frame.getsniffer().stopthread();
		 * frame.setsniffer(null); }
		 */
		lst = (ListData) getModel().get(j);

		// dst = lst.header + "\r\n" + lst.data +
		// "\r\n\r\n---------------------------------\r\n\r\n";

		dst = lst.dataset; // out.write(dst.getBytes(),0,dst.length());

		// System.out.println(dst);
		select sd = null;

		sd = new select(frame, 2, dst);

		// sz=frame.getModel().size();
	}

	public Caller nnn = new Caller();
	// public caller nnn;
	private DefaultListModel model;

	public DefaultListModel getModel() {
		return model;
	}

	public void setModel(DefaultListModel dlm) {
		model = dlm;
	}

	private int select;

	public int getselect() {
		return select;
	}

	private DefaultTableModel model1;

	public DefaultTableModel getModel1() {
		return model1;
	}

	public void setModel1(DefaultTableModel dlm) {
		model1 = dlm;
	}

	private DefaultTableModel model2;

	public DefaultTableModel getModel2() {
		return model2;
	}

	public void setModel2(DefaultTableModel dlm) {
		model2 = dlm;
	}

	private JTable tablle;

	public JTable gettablle() {
		return tablle;
	}

	public void settablle(JTable dlm) {
		tablle = dlm;
	}

	private JTable table2;

	public JTable gettable2() {
		return table2;
	}

	public void settable2(JTable dlm) {
		table2 = dlm;
	}

	private JTable table3;
	private DefaultTableModel model3;

	public DefaultTableModel getModel3() {
		return model3;
	}

	public void setModel3(DefaultTableModel dlm) {
		model3 = dlm;
	}

	private DefaultTreeModel treeModel;
	// absmodel bigData;
	// public VariableGroupListModel getlistmodel(){return bigData;}
	// public void setlistmodel(ListModel lm){bigData=lm;}
	private int type;

	public int getType() {
		return type;
	}

	public void setType(int tprm) {
		type = tprm;
	}

	private int type1;

	public int getType1() {
		return type1;
	}

	public void setType1(int tprm) {
		type1 = tprm;
	}

	private JScrollPane jsp1;

	public JScrollPane getScrollPane1() {
		return jsp1;
	}

	public void setScrollPane1(JScrollPane pjsp) {
		jsp1 = pjsp;
	}

	private JScrollPane jspf;
	private JScrollPane jsp2;

	public JScrollPane getScrollPane2() {
		return jsp2;
	}

	public void setScrollPane2(JScrollPane pjsp) {
		jsp2 = pjsp;
	}

	private JScrollPane jsp3;

	public JScrollPane getScrollPane3() {
		return jsp3;
	}

	public void setScrollPane3(JScrollPane pjsp) {
		jsp3 = pjsp;
	}

	private JTextArea jt;
	private JTextArea jt1;

	public JTextArea getTextArea1() {
		return jt1;
	}

	public void setTextArea1(JTextArea pjt) {
		jt1 = pjt;
	}

	private JList jt2;

	public JList getTextArea2() {
		return jt2;
	}

	public void setTextArea2(JList pjt) {
		jt2 = pjt;
	}

	private JTextArea jt3;

	public JTextArea getTextArea3() {
		return jt3;
	}

	public void setTextArea3(JTextArea pjt) {
		jt3 = pjt;
	}

	private JComboBox nic;

	public JComboBox getComboBox() {
		return nic;
	}

	public void setComboBox(JComboBox pjc) {
		nic = pjc;
	}

	private JComboBox n;

	public JComboBox getComboBox1() {
		return n;
	}

	public void setComboBox1(JComboBox pjc) {
		n = pjc;
	}

	private DefaultListModel nicmdl;

	public DefaultListModel getNicmdl() {
		return nicmdl;
	}

	Action selectLine;
	private JTree tree;
	DefaultMutableTreeNode top;
	JRadioButton wholeCheck11;
	JRadioButton headCheck11;
	JTextArea jts;

	/*
	 * ResultSetter ss = new ResultSetter() { public void setResult(Vector
	 * result,PcapPacketArrayList ss) { threadResult = result; } };
	 */
	/* class constructor */
	public MainMenuHandler(MainGui frm) {

		top = new DefaultMutableTreeNode(
				"Packet Information                                         ");
		JMenuItem menuItem = null;

		f = new FileWrite();
		flag = 0;
		landf = UIManager.getInstalledLookAndFeels();
		frame = frm;
		Font textFont;
		textFont = new Font("TimesNewRoman", Font.BOLD, 12);

		jt3 = new JTextArea();

		jt3.addKeyListener(this);
		jt3.addMouseListener(this);
		jt3.setLineWrap(true);
		jt3.setMinimumSize(new Dimension(600, 600));
		jt3.setEditable(false);
		jt3.setFont(textFont);

		jspf = new JScrollPane(jt3);
		jspf.getViewport().setBackground(Color.WHITE);
		jspf.setBackground(Color.WHITE);

		jspf.getViewport().setBorder(null);
		jspf.setViewportBorder(null);
		jspf.setBorder(null);
		jts = new JTextArea();

		jts.addKeyListener(this);
		jts.addMouseListener(this);
		jts.setLineWrap(true);
		jts.setMinimumSize(new Dimension(600, 600));
		jts.setEditable(false);
		jts.setFont(textFont);

		JScrollPane jpt = new JScrollPane(jts);
		jpt.getViewport().setBackground(Color.WHITE);
		jpt.setBackground(Color.WHITE);

		jpt.getViewport().setBorder(null);
		jpt.setViewportBorder(null);
		jpt.setBorder(null);
		// jt3.setText("Packet Information:");
		JTextArea jtf = new JTextArea();
		JPanel pann = new JPanel();

		pann.add(jpt);
		pann.setLayout(new BoxLayout(pann, BoxLayout.X_AXIS));
		pann.add(jspf);

		// pann.setBorder(BorderFactory.createTitledBorder("Packet Type"));

		jtf.addKeyListener(this);
		jtf.addMouseListener(this);
		jtf.setLineWrap(true);
		jtf.setMinimumSize(new Dimension(600, 600));
		jtf.setEditable(false);

		treeModel = new DefaultTreeModel(top);
		// treeModel = new DefaultTreeModel(top);
		// createNodes(top);

		tree = new JTree(treeModel);
		tree.setEditable(false);
		tree.addKeyListener(this);
		tree.addMouseListener(this);
		tree.getSelectionModel().setSelectionMode(
				TreeSelectionModel.SINGLE_TREE_SELECTION);
		tree.setSize(500, 500);
		tree.addTreeSelectionListener(this);

		tree.setFont(textFont);
		// tree.setShowsRootHandles(true);
		JPanel pan = new JPanel();
		jt1 = new JTextArea(5, 5);
		jt1.setEditable(false);
		jt1.setLineWrap(true);
		jt1.addKeyListener(this);
		jt1.addMouseListener(this);
		jt1.setFont(textFont);
		jt = new JTextArea(0, 0);
		jt.setEditable(false);
		jt.setLineWrap(true);
		jt.addKeyListener(this);
		jt.setFont(textFont);
		jt.addMouseListener(this);
		// jt1.setMinimumSize(new Dimension(500, 500));
		// jt1.setText("Packet type");
		// jt2.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		// jt2.addListSelectionListener(this)
		// jt1.setSize(290,290);
		JTextField jtff = new JTextField("hi");
		JScrollPane jsp5 = new JScrollPane(jt1);
		JScrollPane jsp6 = new JScrollPane(jt);
		jsp5.getViewport().setBackground(Color.WHITE);
		jsp5.setBackground(Color.WHITE);

		jsp5.getViewport().setBorder(null);
		jsp5.setViewportBorder(null);
		jsp5.setBorder(null);

		jsp6.getViewport().setBackground(Color.WHITE);
		jsp6.setBackground(Color.WHITE);

		jsp6.getViewport().setBorder(null);
		jsp6.setViewportBorder(null);
		jsp6.setBorder(null);

		pan.add(jsp5);

		pan.add(jsp6);
		pan.setLayout(new BoxLayout(pan, BoxLayout.Y_AXIS));

		// pan.add(jtf);

		// pan.add(jtf);
		pan.setBorder(BorderFactory.createTitledBorder("Packet Type"));
		jsp3 = new JScrollPane(tree);
		JSplitPane spf5 = new JSplitPane(JSplitPane.VERTICAL_SPLIT, jsp3, pan);
		spf5.setDividerLocation(150);

		JPanel eastPane = new JPanel();

		wholeCheck11 = new JRadioButton("All Packets");
		wholeCheck11.setSelected(true);
		wholeCheck11.setActionCommand("All");
		wholeCheck11.addActionListener(this);
		headCheck11 = new JRadioButton("Anomalous Packets");
		headCheck11.setActionCommand("Only");
		headCheck11.addActionListener(this);
		ButtonGroup group1 = new ButtonGroup();
		group1.add(wholeCheck11);
		group1.add(headCheck11);
		eastPane.setLayout(new BoxLayout(eastPane, BoxLayout.Y_AXIS));
		// eastPane.add(jsp5);
		eastPane.add(wholeCheck11);
		eastPane.setLayout(new BoxLayout(eastPane, BoxLayout.X_AXIS));
		eastPane.add(headCheck11);
		eastPane.setBorder(BorderFactory.createTitledBorder("View"));
		// eastPane.add(Box.createRigidArea(new Dimension(5,5)));
		// eastPane.add(jsp5);

		JSplitPane spf1 = new JSplitPane(JSplitPane.VERTICAL_SPLIT, spf5,
				eastPane);
		spf1.setDividerLocation(320);
		JSplitPane spf = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, spf1, pann); // jspf
		spf.setDividerLocation(320);
		frame.getContentPane().add(spf, BorderLayout.CENTER);
		/*
		 * DefaultMutableTreeNode top3 = new
		 * DefaultMutableTreeNode("Packet Information");
		 * treeModel.insertNodeInto(top3, top, 0);
		 */
		/*
		 * model3 = new DefaultTableModel(); JTable table3 = new JTable(model3);
		 * model3.addColumn("Packet Information"); jsp3=new JScrollPane(table3);
		 * table3.setPreferredScrollableViewportSize(new Dimension(300, 70));
		 * table3.setFillsViewportHeight(true);
		 */

		model = new DefaultListModel();
		/*
		 * model3=new DefaultTableModel(); model3 = new DefaultTableModel();
		 * table3 = new JTable(model3){ public boolean isCellEditable(int row,
		 * int column){ return false; } } ;
		 * table3.setPreferredScrollableViewportSize(new Dimension(500, 70));
		 * table3.setFillsViewportHeight(true);
		 * 
		 * 
		 * 
		 * //Create the scroll pane and add the table to it. jsp3= new
		 * JScrollPane(table3); model3.addColumn("Packet Information");
		 */

		// setLayout(new BorderLayout());

		// frame.getContentPane().add(jsp2, BorderLayout.NORTH);

		model2 = new DefaultTableModel();
		model2 = new DefaultTableModel();
		table2 = new JTable(model2) {
			public boolean isCellEditable(int row, int column) {
				return false;
			}
		};

		table2.addMouseListener(this);
		table2.setFont(textFont);
		table2.addKeyListener(this);
		// jt2.setMinimumSize(new Dimension(300, 300));
		table2.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		table2.getSelectionModel().addListSelectionListener(new RowListener());

		// table2.addTableModelListener(this);
		table2.setPreferredScrollableViewportSize(new Dimension(300, 320));
		table2.setFillsViewportHeight(true);
		jsp2 = new JScrollPane(table2);
		frame.getContentPane().add(jsp2, BorderLayout.NORTH);
		model2.addColumn("No.");
		model2.addColumn("Source IP");
		model2.addColumn("Destination IP");

		model2.addColumn("type");
		TableColumn column = null;

		column = table2.getColumnModel().getColumn(3);

		column.setPreferredWidth(10);
		column = table2.getColumnModel().getColumn(0);

		column.setPreferredWidth(3);
		/*
		 * JButton addButton = new JButton("Add Element"); JButton removeButton
		 * = new JButton("Remove Element"); getContentPane().add(addButton,
		 * BorderLayout.WEST); getContentPane().add(removeButton,
		 * BorderLayout.EAST);
		 */
		JPanel buttonPane = new JPanel(new FlowLayout(FlowLayout.LEFT));
		JButton okButton = new JButton("Previous");
		okButton.add(Box.createRigidArea(new Dimension(50, 10)));
		okButton.setActionCommand("Previous");
		okButton.addActionListener(this);

		JButton cancelButton = new JButton("Next");
		cancelButton.add(Box.createRigidArea(new Dimension(50, 10)));
		cancelButton.setActionCommand("Next");
		cancelButton.addActionListener(this);
		buttonPane.add(okButton);
		buttonPane.add(cancelButton);
		JButton addButton = new JButton("Add");
		addButton.add(Box.createRigidArea(new Dimension(50, 10)));
		addButton.setActionCommand("Selected Packet");
		addButton.addActionListener(this);
		buttonPane.add(addButton);
		buttonPane.setAlignmentX(Component.LEFT_ALIGNMENT);
		JPanel westPane = new JPanel();

		// westPane.add(Box.createRigidArea(new Dimension(5,5)));
		westPane.setLayout(new BoxLayout(westPane, BoxLayout.Y_AXIS));
		westPane.add(jsp2);

		westPane.add(buttonPane);
		JSplitPane sp = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, westPane,
				spf);
		frame.getContentPane().add(sp, BorderLayout.CENTER);
		// JSplitPane sp1 = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, jsp2,
		// jsp3);
		// frame.getContentPane().add(sp1, BorderLayout.CENTER);
		// setIconImage(img.getImage());
		sp.setDividerLocation(310);

		model1 = new DefaultTableModel();
		tablle = new JTable(model1) {
			public boolean isCellEditable(int row, int column) {
				return false;
			}
		};

		model1.addColumn("No.");
		column = tablle.getColumnModel().getColumn(0);
		column.setPreferredWidth(10);
		model1.addColumn("Protocol");
		model1.addColumn("IPLength");
		model1.addColumn("TTL");
		model1.addColumn("Don't Fragment");
		model1.addColumn("More Framgment");
		model1.addColumn("Offset");
		model1.addColumn("SrcPort");
		model1.addColumn("DstPort");
		model1.addColumn("URG");
		model1.addColumn("ACK");
		model1.addColumn("PSH");
		model1.addColumn("RST");
		model1.addColumn("SYN");
		model1.addColumn("FIN");
		model1.addColumn("Window Size");
		model1.addColumn("ICMP Type");
		model1.addColumn("ICMP Code");
		model1.addColumn("ICMP Checksum");
		model1.addColumn("type");
		tablle.getTableHeader().setFont(textFont);

		JTableHeader headerr = tablle.getTableHeader();
		final Font boldFont = headerr.getFont().deriveFont(Font.BOLD);
		final TableCellRenderer headerRenderer = headerr.getDefaultRenderer();
		headerr.setDefaultRenderer(new TableCellRenderer() {
			public Component getTableCellRendererComponent(JTable table,
					Object value, boolean isSelected, boolean hasFocus,
					int row, int column) {
				Component comp = headerRenderer.getTableCellRendererComponent(
						table, value, isSelected, hasFocus, row, column);

				if (column == 2) {

				}

				// System.out.println("HI");
				comp.setFont(boldFont);

				return comp;
			}
		}

		);

		tablle.setFont(textFont);
		String[] toolTipStr = { "Packet Number", "Protoco Type", "IP Length",
				"Time To Leave", "Don't Fragment Flag", "More Fragment Flag",
				"Fragment Offset", "Source Port", "Destination Port",
				"Urgent Flag", "Acknowledgemnt Flag", "Push Flag",
				"Reset Flag", "Synchronous Flag", "Finish Flag", "Window Size",
				"ICMP Type", "ICMP Code", "ICMP Checksum", "Type" };
		ToolTipHeader header = new ToolTipHeader(tablle.getColumnModel());
		header.setToolTipStrings(toolTipStr);
		header.setToolTipText("Default ToolTip TEXT");
		tablle.setTableHeader(header);
		/*
		 * TableColumn column = null; for (int jj = 0; jj < 17; jj++) { column =
		 * table.getColumnModel().getColumn(jj); if (jj == 0) {
		 * column.setPreferredWidth(80); //third column is bigger } if (jj == 1)
		 * { column.setPreferredWidth(90); //third column is bigger } if (jj ==
		 * 2) { column.setPreferredWidth(40); //third column is bigger } if (jj
		 * == 3) { column.setPreferredWidth(180); //third column is bigger
		 * 
		 * } if (jj == 4) { column.setPreferredWidth(200); //third column is
		 * bigger
		 * 
		 * }
		 * 
		 * }
		 */

		// model1.addRow(new Object[]{"v1", "v2"});
		// final JTable table = new JTable(data, columnNames);
		tablle.setPreferredScrollableViewportSize(new Dimension(500, 70));
		tablle.setFillsViewportHeight(true);
		tablle.addMouseListener(this);
		tablle.addKeyListener(this);
		/*
		 * if (DEBUG) { table.addMouseListener(new MouseAdapter() { public void
		 * mouseClicked(MouseEvent e) { printDebugData(table); } }); }
		 */

		// Create the scroll pane and add the table to it.
		JScrollPane scrollPane = new JScrollPane(tablle);

		// Add the scroll pane to this panel.
		// add(scrollPane);
		JSplitPane sp1 = new JSplitPane(JSplitPane.VERTICAL_SPLIT, sp,
				scrollPane);
		frame.getContentPane().add(sp1, BorderLayout.CENTER);
		sp1.setDividerLocation(380);
		// addButton.addActionListener(new ActionListener() {
		// ljp=frame.getModel();
		// table=frame.getModel2();
		ljp = getModel();
		table = getModel2();
		frame.addKeyListener(this);
		menubar = new JMenuBar();
		menubar.addKeyListener(this);
		popup = new JPopupMenu();
		aboutmenu = new JMenu("About");
		aboutmenu.setMnemonic(KeyEvent.VK_A);
		datasetmenu = new JMenu("Add to Dataset");
		datasetmenu.setMnemonic(KeyEvent.VK_A);
		sniffermenu = new JMenu("Packet Sniffing");
		sniffermenu.setMnemonic(KeyEvent.VK_P);
		landfmenu = new JMenu("Learn");
		landfmenu.setMnemonic(KeyEvent.VK_L);

		menuItem = new JMenuItem("About     Ctrl+H");
		menuItem.setActionCommand("About");
		menuItem.addActionListener(this);
		aboutmenu.add(menuItem);
		// landf = UIManager.getInstalledLookAndFeels();
		/*
		 * for(int j = 0; j < landf.length; j++) { menuItem = new
		 * JMenuItem(getclassname(landf[j].getClassName()));
		 * menuItem.addActionListener(this); landfmenu.add(menuItem); }
		 */
		menuItem = new JMenuItem("Naive Bayes     Ctrl+L");
		menuItem.setActionCommand("Naive Bayes");
		menuItem.addActionListener(this);
		landfmenu.add(menuItem);
		menuItem = new JMenuItem("Selected Packet     Ctrl+M");
		menuItem.setActionCommand("Selected Packet");
		menuItem.addActionListener(this);
		datasetmenu.add(menuItem);
		menuItem = new JMenuItem("All Packets               Ctrl+N");
		menuItem.setActionCommand("All Packets");
		menuItem.addActionListener(this);
		datasetmenu.add(menuItem);
		menuItem = new JMenuItem("From Device     Ctrl+D");
		menuItem.setActionCommand("From Device");
		menuItem.addActionListener(this);
		popup.add(menuItem);
		menuItem = new JMenuItem("From Device     Ctrl+D ");
		menuItem.setActionCommand("From Device");
		menuItem.addActionListener(this);
		sniffermenu.add(menuItem);
		menuItem = new JMenuItem("From File           Ctrl+F");
		menuItem.setActionCommand("From File");
		menuItem.addActionListener(this);
		popup.add(menuItem);
		menuItem = new JMenuItem("From File           Ctrl+F");
		menuItem.setActionCommand("From File");
		menuItem.addActionListener(this);
		sniffermenu.add(menuItem);

		menuItem = new JMenuItem("Stop                   Ctrl+S");
		menuItem.setActionCommand("Stop");
		menuItem.addActionListener(this);
		popup.add(menuItem);
		menuItem = new JMenuItem("Stop                   Ctrl+S");
		menuItem.setActionCommand("Stop");
		menuItem.addActionListener(this);
		sniffermenu.add(menuItem);

		menuItem = new JMenuItem("Naive Bayes     Ctrl+L");
		menuItem.setActionCommand("Naive Bayes");
		menuItem.addActionListener(this);
		popup.add(menuItem);
		/*
		 * menuItem = new JMenuItem("Learn Structure");
		 * menuItem.addActionListener(this); sniffermenu.add(menuItem);
		 */
		menuItem = new JMenuItem("Next                   Right arrow");
		menuItem.setActionCommand("Next");
		menuItem.addActionListener(this);
		popup.add(menuItem);
		menuItem = new JMenuItem("Previous           Left arrow ");
		menuItem.setActionCommand("Previous");
		menuItem.addActionListener(this);
		popup.add(menuItem);
		menuItem = new JMenuItem("Add                    Ctrl+M");
		menuItem.setActionCommand("Selected Packet");
		menuItem.addActionListener(this);
		popup.add(menuItem);
		menuItem = new JMenuItem("Exit                     Alt+F4");
		menuItem.setActionCommand("Exit");
		menuItem.addActionListener(this);
		popup.add(menuItem);
		menuItem = new JMenuItem("Exit                    Alt+F4");
		menuItem.setActionCommand("Exit");
		menuItem.addActionListener(this);
		okButton = new JButton("OK");
		okButton.setActionCommand("OK");
		okButton.addActionListener(this);
		headCheck = new JRadioButton("Attack packet");
		headCheck.setActionCommand("Attack");
		headCheck.addActionListener(this);
		sniffermenu.add(menuItem);
		menubar.add(sniffermenu);
		menubar.add(landfmenu);
		menubar.add(datasetmenu);
		menubar.add(aboutmenu);
		// frame.setpopup(popup);
		frame.setJMenuBar(menubar);

	}

	/*
	 * Function that strips of the actual class name from a fully-qualified java
	 * class name
	 */
	String getclassname(String originalname) {
		return originalname.substring(originalname.lastIndexOf(".") + 1);
	}

	public void keyPressed(KeyEvent e) {
		dumpInfo("Pressed", e);
	}

	public void keyReleased(KeyEvent e) {
		// dumpInfo("Released", e);
	}

	public void keyTyped(KeyEvent e) {
		// dumpInfo("Typed", e);
	}

	private void dumpInfo(String s, KeyEvent e) {
		System.out.println(s);
		int code = e.getKeyCode();
		/*
		 * System.out.println("\tCode: " + code); System.out.println("\tChar: "
		 * + e.getKeyChar());
		 * 
		 * System.out.println("\tMods: " + mods);
		 */

		int mods = e.getModifiersEx();

		if (code == 37)
			previous(getanalomous());

		if (code == 68 && mods == 128) {
			select sd = null;
			sd = new select(frame, 1, null);
		}

		if (code == 70 && mods == 128)
			fromfile(8, 9);

		if (code == 83 && mods == 128) {
			if (frame.getsniffer() != null) {
				frame.getsniffer().stopthread();
				frame.setsniffer(null);
			}

		}

		if (code == 76 && mods == 128) {
			learn();
		}

		if (code == 77 && mods == 128) {
			selectpacket();
		}

		if (code == 78 && mods == 128) {
			select sd = null;
			sd = new select(frame, 0, null);
		}

		if (code == 72 && mods == 128) {

			AboutDialog add;

			add = new AboutDialog(frame);
		}

		if (code == 39 && (nnn.vector.size() - count) > 20) {
			nextflag = nnn.vector.size();
			next(getanalomous());

		} else if (frame.getsniffer() == null) {
			next(getanalomous());

		} else if (code == 39 && frame.getsniffer().isAlive() == false) {
			next(getanalomous());
		}

	}

	/* Function that handles menu events. */
	public void actionPerformed(ActionEvent e) {
		FileOutputStream out = null;
		int sz = 0;

		try {
			for (int i = 0; i < landf.length; i++) {
				if (getclassname(landf[i].getClassName()).equals(
						e.getActionCommand())) {
					UIManager.setLookAndFeel(landf[i].getClassName());
					SwingUtilities.updateComponentTreeUI(frame);
					break;
				}
			}

		} catch (Exception ex) {
			ex.printStackTrace();
		}

		if (e.getActionCommand().equals("comboBoxChanged")) {
			frame.setType(frame.getComboBox().getSelectedIndex() - 1);

			frame.setType1(frame.getComboBox1().getSelectedIndex() - 1);

		} else if (e.getActionCommand().equals("Naive Bayes")) {
			learn();

		} else if (e.getActionCommand().equals("Next")) {
			if (nnn.vector == null) {
				JOptionPane.showMessageDialog(frame,
						"Start capturing from Packet Sniffing menu.",
						"Packets not captured yet", JOptionPane.ERROR_MESSAGE);
				return;
			}

			if ((nnn.vector.size() - count) > 20) {
				nextflag = nnn.vector.size();
				next(getanalomous());

			} else if (frame.getsniffer() == null) {
				next(getanalomous());

			} else if (frame.getsniffer().isAlive() == false) {
				next(getanalomous());

			} else
				return;

		} else if (e.getActionCommand().equals("Previous")) {
			previous(getanalomous());

		} else if (e.getActionCommand().equals("From Device")) {

			select sd = null;
			sd = new select(frame, 1, null);

		}

		else if (e.getActionCommand().equals("From File")) {
			fromfile(-1, -1);

		} else if (e.getActionCommand().equals("Stop")) {
			if (frame.getsniffer() != null) {
				frame.getsniffer().stopthread();
				frame.setsniffer(null);
			}

		} else if (e.getActionCommand().equals("Normal")) {
			// System.out.println("OKKKK");

		} else if (e.getActionCommand().equals("All Packets")) {

			select sd = null;
			sd = new select(frame, 0, null);

		} else if (e.getActionCommand().equals("Selected Packet")) {
			selectpacket();

		} else if (e.getActionCommand().equals("All")) {
			if (nnn.vector == null) {
				JOptionPane.showMessageDialog(frame,
						"Start capturing from Packet Sniffing menu.",
						"Packets not captured yet", JOptionPane.ERROR_MESSAGE);
				wholeCheck11.setSelected(true);
				return;
			}

			analomous = 0;
			anaflag = 0;
			normalflag = 0;
			next(analomous);

		} else if (e.getActionCommand().equals("Only")) {

			if (nnn.analomous == null) {

				JOptionPane.showMessageDialog(frame,
						"Anomalous packets are not detected yet.", "Invalid",
						JOptionPane.ERROR_MESSAGE);
				wholeCheck11.setSelected(true);
				return;
			}

			if (nnn.analomous.size() == 0) {

				JOptionPane.showMessageDialog(frame,
						"Anomalous packets are not detected yet.", "Invalid",
						JOptionPane.ERROR_MESSAGE);
				wholeCheck11.setSelected(true);
				return;
			}

			analomous = 1;
			anaflag = 0;
			normalflag = 0;
			next(analomous);

		} else if (e.getActionCommand().equals("Exit")) {
			System.exit(0);

		} else if (e.getActionCommand().equals("About")) {

			AboutDialog add;

			add = new AboutDialog(frame);

			// selectdialog sd=null;
			// sd=new selectdialog(frame);System.out.println(sd.getvalue());
		}
	}

	class select extends JDialog implements ActionListener {
		private JScrollPane jsp;
		private JEditorPane helpfile;
		private int value;
		private int file;
		private int option;
		private String info;
		private boolean monitor = false;
		private boolean logging = false;
		JComboBox adapterComboBox;
		JTextField filterField, caplenField;
		JRadioButton wholeCheck, headCheck, userCheck, wholeCheck1, headCheck1;
		JCheckBox promiscCheck;

		public select(JFrame owner, int opt, String in) {
			super(owner, "Options", true);
			option = opt;
			info = in;

			if (option == 0 || option == 2) {

				value = 0;
				file = 3;
				// setSize(500,500);
				Dimension screenSize = Toolkit.getDefaultToolkit()
						.getScreenSize();
				int w = 550;
				int h = 300;
				setLocation(w, h);
				// setLocationRelativeTo(null);

				JPanel caplenPane = new JPanel();
				caplenPane
						.setLayout(new BoxLayout(caplenPane, BoxLayout.Y_AXIS));

				wholeCheck = new JRadioButton("Normal packet");
				wholeCheck.setSelected(true);
				wholeCheck.setActionCommand("Normal");
				wholeCheck.addActionListener(this);
				headCheck = new JRadioButton("Attack packet");
				headCheck.setActionCommand("Attack");
				headCheck.addActionListener(this);

				ButtonGroup group = new ButtonGroup();
				group.add(wholeCheck);
				group.add(headCheck);

				caplenPane.add(wholeCheck);
				caplenPane.add(headCheck);

				caplenPane.setBorder(BorderFactory
						.createTitledBorder("Select Type"));
				caplenPane.setAlignmentX(Component.LEFT_ALIGNMENT);

				JPanel buttonPane = new JPanel(new FlowLayout(FlowLayout.RIGHT));
				buttonPane
						.setLayout(new BoxLayout(buttonPane, BoxLayout.Y_AXIS));
				JButton okButton = new JButton("OK");
				okButton.setActionCommand("OK");
				okButton.addActionListener(this);

				JButton cancelButton = new JButton("Cancel");
				cancelButton.setActionCommand("Cancel");

				cancelButton.addActionListener(this);
				buttonPane.add(okButton);
				buttonPane.add(Box.createRigidArea(new Dimension(5, 10)));
				buttonPane.add(cancelButton);
				buttonPane.setAlignmentX(Component.LEFT_ALIGNMENT);

				JPanel caplenPane1 = new JPanel();
				caplenPane1.setLayout(new BoxLayout(caplenPane1,
						BoxLayout.Y_AXIS));

				wholeCheck1 = new JRadioButton("Old File");
				wholeCheck1.setSelected(true);
				wholeCheck1.setActionCommand("Old");
				wholeCheck1.addActionListener(this);
				headCheck1 = new JRadioButton("New File");
				headCheck1.setActionCommand("New");
				headCheck1.addActionListener(this);

				ButtonGroup group1 = new ButtonGroup();
				group1.add(wholeCheck1);
				group1.add(headCheck1);

				caplenPane1.add(wholeCheck1);
				caplenPane1.add(headCheck1);

				caplenPane1.setBorder(BorderFactory
						.createTitledBorder("Write To"));
				caplenPane1.setAlignmentX(Component.LEFT_ALIGNMENT);

				JPanel westPane = new JPanel();

				westPane.add(Box.createRigidArea(new Dimension(10, 10)));
				// westPane.setLayout(new BoxLayout(westPane,BoxLayout.Y_AXIS));
				westPane.add(caplenPane);
				westPane.add(caplenPane1);
				westPane.add(Box.createRigidArea(new Dimension(5, 10)));
				westPane.add(buttonPane);
				// westPane.add(Box.createRigidArea(new Dimension(5,5)));

				// getContentPane().setLayout(new
				// BoxLayout(getContentPane(),BoxLayout.X_AXIS));
				// getContentPane().add(Box.createRigidArea(new
				// Dimension(10,10)));
				getContentPane().add(westPane);
				// getContentPane().add(Box.createRigidArea(new
				// Dimension(10,10)));
				// getContentPane().add(eastPane);
				// getContentPane().add(Box.createRigidArea(new
				// Dimension(10,10)));
				pack();

				setDefaultCloseOperation(DISPOSE_ON_CLOSE);
				setVisible(true);

			} else {
				Dimension screenSize = Toolkit.getDefaultToolkit()
						.getScreenSize();
				int w = 300;
				int h = 300;
				setLocation(w, h);

				value = 0;
				List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be
																// filled with
																// NICs
				StringBuilder errbuf = new StringBuilder(); // For any error
															// msgs

				/***************************************************************************
				 * # * First get a list of devices on this system #
				 **************************************************************************/
				int r = Pcap.findAllDevs(alldevs, errbuf);

				if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
					// System.err.printf("Can't read list of devices, error is %s",
					// errbuf
					// .toString());
					return;
				}

				int length = 0;

				for (PcapIf device : alldevs)
					length++;

				// System.out.println("Network devices found:"+length);

				int j = 0;

				String[] interfaces = new String[length + 1];

				interfaces[j++] = new String(
						"Please select a network interface.");

				for (PcapIf device : alldevs) {
					String description = (device.getDescription() != null) ? device
							.getDescription() : "No description available";
					// System.out.printf("%d: %s [%s]\n", j, device.getName(),
					// description);
					interfaces[j++] = new String(j - 1 + ": "
							+ device.getName() + "(" + description + ")");
					// j++;
				}

				adapterComboBox = new JComboBox(interfaces);
				JPanel adapterPane = new JPanel();
				adapterPane.add(adapterComboBox);
				adapterPane.setBorder(BorderFactory
						.createTitledBorder("Choose capture device"));
				adapterPane.setAlignmentX(Component.LEFT_ALIGNMENT);

				JPanel buttonPane = new JPanel(new FlowLayout(FlowLayout.LEFT));
				// buttonPane.setLayout(new
				// BoxLayout(buttonPane,BoxLayout.Y_AXIS));
				JButton okButton = new JButton("OK");
				okButton.setActionCommand("OK");
				okButton.addActionListener(this);

				JButton cancelButton = new JButton("Cancel");
				cancelButton.setActionCommand("Cancel");

				cancelButton.addActionListener(this);
				buttonPane.add(okButton);
				buttonPane.add(Box.createRigidArea(new Dimension(5, 10)));
				buttonPane.add(cancelButton);
				buttonPane.setAlignmentX(Component.LEFT_ALIGNMENT);
				JPanel westPane = new JPanel();

				// westPane.add(Box.createRigidArea(new Dimension(10,10)));
				// westPane.setLayout(new BoxLayout(westPane,BoxLayout.Y_AXIS));
				JPanel caplenPane = new JPanel();
				// caplenPane.setLayout(new
				// BoxLayout(caplenPane,BoxLayout.X_AXIS));

				wholeCheck = new JRadioButton("Monitor+Browse");
				wholeCheck.setSelected(true);
				wholeCheck.setActionCommand("Browse");
				wholeCheck.addActionListener(this);
				headCheck = new JRadioButton("Monitor");
				headCheck.setActionCommand("Monitor");
				headCheck.addActionListener(this);

				ButtonGroup group = new ButtonGroup();
				group.add(wholeCheck);
				group.add(headCheck);

				caplenPane.add(wholeCheck);
				caplenPane.add(headCheck);

				caplenPane.setBorder(BorderFactory
						.createTitledBorder("Select Mode"));
				caplenPane.setAlignmentX(Component.LEFT_ALIGNMENT);

				JPanel caplenPane1 = new JPanel();
				// caplenPane1.setLayout(new
				// BoxLayout(caplenPane1,BoxLayout.Y_AXIS));

				wholeCheck1 = new JRadioButton("Yes");
				wholeCheck1.setSelected(false);
				wholeCheck1.setActionCommand("Yes");
				wholeCheck1.addActionListener(this);
				headCheck1 = new JRadioButton("No");
				headCheck1.setActionCommand("No");
				headCheck1.setSelected(true);
				headCheck1.addActionListener(this);

				ButtonGroup group1 = new ButtonGroup();
				group1.add(wholeCheck1);
				group1.add(headCheck1);

				caplenPane1.add(wholeCheck1);
				caplenPane1.add(headCheck1);

				caplenPane1.setBorder(BorderFactory
						.createTitledBorder("Anomalous Packet Logging Mode"));
				caplenPane1.setAlignmentX(Component.LEFT_ALIGNMENT);

				westPane.add(adapterPane);
				westPane.add(caplenPane);
				westPane.add(caplenPane1);
				westPane.setLayout(new BoxLayout(westPane, BoxLayout.Y_AXIS));
				westPane.add(Box.createRigidArea(new Dimension(5, 30)));
				westPane.add(buttonPane);
				westPane.add(Box.createRigidArea(new Dimension(5, 5)));

				getContentPane().setLayout(
						new BoxLayout(getContentPane(), BoxLayout.X_AXIS));
				getContentPane()
						.add(Box.createRigidArea(new Dimension(10, 10)));
				getContentPane().add(westPane);
				getContentPane()
						.add(Box.createRigidArea(new Dimension(10, 10)));
				// getContentPane().add(eastPane);
				getContentPane()
						.add(Box.createRigidArea(new Dimension(10, 10)));
				pack();
				setDefaultCloseOperation(DISPOSE_ON_CLOSE);
				setVisible(true);
			}
		}

		public int getvalue() {
			return value;
		}

		public void actionPerformed(ActionEvent evt) {
			String cmd = evt.getActionCommand();

			if (cmd.equals("Normal")) {
				value = 0;
				// System.out.println(value);

			} else if (cmd.equals("Attack")) {

				value = 1;
				// System.out.println(value);

			} else if (cmd.equals("Old")) {

				file = 3;
				// System.out.println(file);

			} else if (cmd.equals("New")) {

				file = 4;
				// System.out.println(file);

			} else if (cmd.equals("Monitor")) {
				monitor = true;

			} else if (cmd.equals("Yes")) {
				logging = true;

			} else if (cmd.equals("comboBoxChanged")) {

				int i = adapterComboBox.getSelectedIndex() - 1;

			} else if (cmd.equals("OK")) {

				if (option == 0) {
					dispose();
					fromfile(file, value);

				}

				if (option == 1) {
					int i = adapterComboBox.getSelectedIndex() - 1;
					dispose();
					// System.out.print("dispose"+i);
					fromdevice(i, monitor, logging);
				}

				if (option == 2) {
					dispose();
					singlepacket(info, value, file);
				}

			} else if (cmd.equals("Cancel")) {
				dispose();
			}
		}
	}

	public void singlepacket(String info, int value, int number) {
		if (value == 0)
			info += "normal";
		else
			info += "attack";

		// System.out.println(info);
		if (number == 4) {

			f.write("protocol\tiplength\tttl\tdf\tmf\toffset\tflood\tscan\turg\tack\tpsh\trst\tsyn\tfin\twinsize\ticmpflood\ticmptype\ticmpcheksum\ttype",
					100, false);

			f.write(info, 100, true);
		}

		if (number == 3) {
			f.write(info, 100, true);
		} // System.out.println(info1);

		JOptionPane.showMessageDialog(frame,
				"Packet features added to dataset.", "Success",
				JOptionPane.INFORMATION_MESSAGE);
	}

	public void mouseClicked(MouseEvent e) {

		if (SwingUtilities.isLeftMouseButton(e) && e.getClickCount() == 1) {
			// selectLine.actionPerformed( null );

		}
	}

	public void mouseEntered(MouseEvent e) {
	}

	public void mouseExited(MouseEvent e) {
	}

	public void mousePressed(MouseEvent e) {
	}

	private Action getAction(String name) {
		Action action = null;
		Action[] actions = jt1.getActions();

		for (int i = 0; i < actions.length; i++) {
			if (name.equals(actions[i].getValue(Action.NAME).toString())) {
				action = actions[i];
				break;
			}
		}

		return action;
	}

	public void mouseReleased(MouseEvent e) {
		int i = e.getButton();

		if (i == MouseEvent.BUTTON3) {
			popup.show(e.getComponent(), e.getX(), e.getY());
		}
	}

	/* Method that responds to changes in the network interface combo box. */
	/*
	 * public void actionPerformed(ActionEvent e) {
	 * if(e.getActionCommand().equals("comboBoxChanged")) { type =
	 * nic.getSelectedIndex()-1; //System.out.print("type"+type);
	 * type1=n.getSelectedIndex()-1; //System.out.print("type1"+type1); }
	 * jt2.requestFocusInWindow(); }
	 */

	/* Method that responds to changes in the packet listbox. */
	public void valueChanged(TreeSelectionEvent e) {
		// Returns the last path element of the selection.
		// This method is useful only when the selection model allows a single
		// selection.
		String tcpinfo = null;
		String udpinfo = null;
		String icmpinfo = null;
		String frameinfo = null;
		String ethernetinfo = null;
		String myppoeinfo = null;
		String typeinfo = null;
		String ipinfo = null;
		DefaultMutableTreeNode node = (DefaultMutableTreeNode) tree
				.getLastSelectedPathComponent();

		if (node == null)
			// Nothing is selected.
			return;

		if (tmp == null)
			return;

		Object nodeInfo = node.getUserObject();

		frameinfo = "Frame\n\n";

		frameinfo += "Timestamp\n";

		frameinfo += "Capture Length\n";

		frameinfo += "Wire Length:\n";

		ethernetinfo = "Ethernet Protocol\n\n";

		ethernetinfo += "Source\n";

		ethernetinfo += "Destination\n";

		ethernetinfo += "Type";

		myppoeinfo = "PPPOE" + "\n\n";

		myppoeinfo += "Version\n";

		myppoeinfo += "Type\n";

		myppoeinfo += "SessionId\n";

		myppoeinfo += "Length\n";

		myppoeinfo += "NextId:";

		ipinfo = "Internet Protocol" + "\n\n";

		ipinfo += "Version\n";

		ipinfo += "Source IP\n";

		ipinfo += "Destination IP\n";

		ipinfo += "Header Length\n";

		ipinfo += "Checksum\n";

		ipinfo += "IP Type\n";

		ipinfo += "IP Length\n";

		ipinfo += "Time To Leave\n";

		ipinfo += "Don't Fragment\n";

		ipinfo += "More Fragment\n";

		ipinfo += "Offset";

		tcpinfo = "TCP\n\n";

		tcpinfo += "Source Port\n";

		tcpinfo += "Destination Port\n";

		tcpinfo += "Urgent\n";

		tcpinfo += "Acknowledgement number\n";

		tcpinfo += "Sequence number\n";

		tcpinfo += "Checksum\n";

		tcpinfo += "Flags\n";

		tcpinfo += "Urgent\n";

		tcpinfo += "Acknowledgment\n";

		tcpinfo += "Push\n";

		tcpinfo += "Reset\n";

		tcpinfo += "Synchronize\n";

		tcpinfo += "Finish\n";

		tcpinfo += "Window size";

		udpinfo = "User Datagram Protocol\n\n";

		udpinfo += "Source Port\n";

		udpinfo += "Destination Port\n";

		udpinfo += "Checksum\n";

		udpinfo += "Length\n";

		icmpinfo = "ICMP\n\n";

		icmpinfo += "ICMP Type\n";

		icmpinfo += "ICMP code\n";

		icmpinfo += "Checksum\n";

		typeinfo = "\n\nProbability(Packet==normal)\n";

		typeinfo += "Packet is classified as";

		if (nodeInfo == "Frame") {
			jt3.setText(tmp.frame);
			jts.setText(frameinfo);
		}

		if (nodeInfo == "Ethernet Protocol") {
			jt3.setText(tmp.ethernet);
			jts.setText(ethernetinfo);
		}

		if (nodeInfo == "PPPOE") {
			jt3.setText(tmp.myppoe);
			jts.setText(myppoeinfo);
		}

		if (nodeInfo == "Internet Protocol") {
			jts.setText(ipinfo);

			jt3.setText(tmp.ip);
		}

		if (nodeInfo == "Transmission Control Protocol") {
			jts.setText(tcpinfo);
			jt3.setText(tmp.tcp);
		}

		if (nodeInfo == "User Datagram Protocol") {
			jts.setText(udpinfo);
			jt3.setText(tmp.udp);
		}

		if (nodeInfo == "ICMP") {

			jts.setText(icmpinfo);
			jt3.setText(tmp.icmp);
		}

		if (nodeInfo == "type") {

			jts.setText(typeinfo);
			jt3.setText(tmp.packettype);

		}
	}

	public void valueChanged(ListSelectionEvent e) {

		ListData tmp;

		if (e.getValueIsAdjusting() == false) {
			if (jt2.getSelectedIndex() != -1) {
				jt3.setCaretPosition(0);
				select = jt2.getSelectedIndex();
				tmp = (ListData) model.elementAt(select);

				// System.out.println("select:"+select);
				jt3.insert(tmp.data, 0);
				// System.out.println(tmp.data);

			}
		}

	}

	class MyTreeModelListener implements TreeModelListener {
		public void treeNodesChanged(TreeModelEvent e) {
			DefaultMutableTreeNode node;
			node = (DefaultMutableTreeNode) (e.getTreePath()
					.getLastPathComponent());
			// System.out.print("Hi");
			/*
			 * If the event lists children, then the changed node is the child
			 * of the node we have already gotten. Otherwise, the changed node
			 * and the specified node are the same.
			 */

			try {
				int index = e.getChildIndices()[0];
				node = (DefaultMutableTreeNode) (node.getChildAt(index));

			} catch (NullPointerException exc) {
			}

			// System.out.println("The user has finished editing the node.");
			// System.out.println("New value: " + node.getUserObject());
		}

		public void treeNodesInserted(TreeModelEvent e) {
		}

		public void treeNodesRemoved(TreeModelEvent e) {
		}

		public void treeStructureChanged(TreeModelEvent e) {
		}

	}

	private class RowListener implements ListSelectionListener {
		public void valueChanged(ListSelectionEvent event) {

			if (event.getValueIsAdjusting()) {
				select = table2.getSelectionModel().getLeadSelectionIndex();

				tmp = (ListData) model.elementAt(select);
				// System.out.println(tmp.data);
				// String[] arr=new String[1];
				// arr[0]=tmp.data;
				// model3.insertRow(0,new Object[]{arr[0]});
				// table3.setDefaultRenderer(Object.class, new MyRen(tmp.data));
				// System.out.println(tmp.ip);

				// top.add(top1);
				// treeModel.removeNodeFromParent(top1);
				// treeModel.setRoot(null);
				String ipinfo = null;
				DefaultMutableTreeNode node1;
				Object n = new Object();
				UIManager.put("Tree.rowHeight", new Integer(36));
				int i = 0;
				n = treeModel.getRoot();
				ipinfo = "Internet Protocol" + "\n\n";
				ipinfo += "Version\n";
				ipinfo += "Source IP\n";
				ipinfo += "Destination IP\n";
				ipinfo += "Header Length\n";
				ipinfo += "Checksum\n";
				ipinfo += "IP Type\n";
				ipinfo += "IP Length\n";
				ipinfo += "Time To Live\n";
				ipinfo += "Don't Fragment\n";
				ipinfo += "More Fragment\n";
				ipinfo += "Offset";
				DefaultMutableTreeNode top1;
				DefaultMutableTreeNode top2;
				DefaultMutableTreeNode top3;
				DefaultMutableTreeNode topp;

				if (tmp == null)
					return;

				if (tmp.type == "normal") {

					jts.setForeground(Color.black);
					jt3.setForeground(Color.black);
					jt1.setForeground(Color.black);

				} else {

					jts.setForeground(Color.red);
					jt3.setForeground(Color.red);
					jt1.setForeground(Color.red);
				}

				jts.setText(ipinfo);
				jt3.setText(tmp.ip);
				jt1.setText(tmp.data);

				while (treeModel.getChildCount(n) > 0) {
					topp = (DefaultMutableTreeNode) treeModel.getChild(n, 0);
					treeModel.removeNodeFromParent(topp);
				}

				if (tmp.frame != null) {
					// DefaultMutableTreeNode top1;
					top1 = new DefaultMutableTreeNode("Frame");

					treeModel.insertNodeInto(top1, top, i++);
				}

				if (tmp.ethernet != null) {
					// DefaultMutableTreeNode top1;
					top1 = new DefaultMutableTreeNode("Ethernet Protocol");
					treeModel.insertNodeInto(top1, top, i++);
				}

				if (tmp.myppoe != null) {
					// DefaultMutableTreeNode top1;
					top1 = new DefaultMutableTreeNode("PPPOE");
					treeModel.insertNodeInto(top1, top, i++);
				}

				if (tmp.ip != null) {
					// DefaultMutableTreeNode top1;
					top1 = new DefaultMutableTreeNode("Internet Protocol");
					treeModel.insertNodeInto(top1, top, i++);
				}

				if (tmp.tcp != null) {
					// DefaultMutableTreeNode top1;
					top1 = new DefaultMutableTreeNode(
							"Transmission Control Protocol");
					treeModel.insertNodeInto(top1, top, i++);
				}

				if (tmp.udp != null) {
					// DefaultMutableTreeNode top1;
					top1 = new DefaultMutableTreeNode("User Datagram Protocol");
					treeModel.insertNodeInto(top1, top, i++);
				}

				if (tmp.icmp != null) {
					// DefaultMutableTreeNode top1;
					top1 = new DefaultMutableTreeNode("ICMP");
					treeModel.insertNodeInto(top1, top, i++);
				}

				if (tmp.packettype != null) {
					// DefaultMutableTreeNode top1;
					top1 = new DefaultMutableTreeNode("type");
					treeModel.insertNodeInto(top1, top, i++);
				}

				tree.expandRow(0);

				// System.out.println(treeModel.getChild(n,0));

				// top.add(top1);
				// treeModel.insertNodeInto(top, top1, 0);
				// jsp3.add(tree);
				/*
				 * if(tmp.type=="normal") jt3.setForeground(Color.black); else
				 * jt3.setForeground(Color.red); jt3.setText(tmp.data); return;
				 */
			}

		}
	}
}

class MyRende extends DefaultTableCellRenderer {
	private int coll;

	public MyRende(int j) {

		coll = j;
	}

	public Component getTableCellRendererComponent(JTable table, Object value,
			boolean isSelected, boolean hasFocus, int row, int col) {
		Component comp1 = super.getTableCellRendererComponent(table, value,
				isSelected, hasFocus, row, col);

		String s = table.getModel().getValueAt(row, coll).toString();

		if (s == "normal") {
			comp1.setBackground(Color.white);
			comp1.setForeground(Color.black);
			// comp1.setForeground(Color.black);
		}

		else {
			comp1.setBackground(Color.black);
			comp1.setForeground(Color.white);
			// comp1.setForeground(Color.red);
			// System.out.println("green"+":"+str);
		}

		return (comp1);
	}
}

class ToolTipHeader extends JTableHeader {
	String[] toolTips;

	public ToolTipHeader(TableColumnModel model) {
		super(model);
	}

	public String getToolTipText(MouseEvent e) {
		int col = columnAtPoint(e.getPoint());
		int modelCol = getTable().convertColumnIndexToModel(col);
		String retStr;

		try {
			retStr = toolTips[modelCol];

		} catch (NullPointerException ex) {
			retStr = "";

		} catch (ArrayIndexOutOfBoundsException ex) {
			retStr = "";
		}

		if (retStr.length() < 1) {
			retStr = super.getToolTipText(e);
		}

		return retStr;
	}

	public void setToolTipStrings(String[] toolTips) {
		this.toolTips = toolTips;
	}
}
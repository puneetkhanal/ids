package com.ids;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;

import com.ids.packet.SnifferThread;

public class MainGui extends JFrame {
	private JPopupMenu popup;

	public JPopupMenu getpopup() {
		return popup;
	}

	public void setpopup(JPopupMenu jpm) {
		popup = jpm;
	}

	private SnifferThread dt;

	public SnifferThread getsniffer() {
		return dt;
	}

	public void setsniffer(SnifferThread pdt) {
		dt = pdt;
	}

	private DefaultListModel model;

	public DefaultListModel getModel() {
		return model;
	}

	public void setModel(DefaultListModel dlm) {
		model = dlm;
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

	private JTable table;

	public JTable gettable1() {
		return table;
	}

	public void settable1(JTable dlm) {
		table = dlm;
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

	private int select;

	public int getselect() {
		return select;
	}

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

	private UIManager.LookAndFeelInfo[] landf;

	public UIManager.LookAndFeelInfo[] getLandF() {
		return landf;
	}

	public void setLandF(UIManager.LookAndFeelInfo[] plandf) {
		landf = plandf;
	}

	private MainMenuHandler mmh;

	public MainMenuHandler getMenuHandler() {
		return mmh;
	}

	public void setMenuHandler(MainMenuHandler pmmh) {
		mmh = pmmh;
	}

	/* The class constructor */
	public MainGui() {
		java.net.URL imageURL = null;
		popup = null;
		dt = null;
		jt1 = null;
		jt2 = null;
		jsp1 = null;
		jsp2 = null;
		landf = null;
		mmh = null;
		type = -1;
		type1 = -1;

		setSize(1000, 800);
		setLocationRelativeTo(null);
		setDefaultCloseOperation(EXIT_ON_CLOSE);

		mmh = new MainMenuHandler(this);
	}

}
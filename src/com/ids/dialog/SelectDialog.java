package com.ids.dialog;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

public class SelectDialog extends JDialog implements ActionListener {
	private JScrollPane jsp;
	private JEditorPane helpfile;
	private int value;

	JTextField filterField, caplenField;
	JRadioButton wholeCheck, headCheck, userCheck, wholeCheck1, headCheck1;
	JCheckBox promiscCheck;

	public SelectDialog(JFrame owner) {

		super(owner, "About Intelligent Intrustion Detection");
		setSize(600, 300);
		/*
		 * String[] names=new String[2]; for(int i=0;i<names.length;i++)
		 * names[i]="a"; adapterComboBox=new JComboBox(names); value=0; JPanel
		 * adapterPane=new JPanel(); adapterPane.add(adapterComboBox);
		 * adapterPane
		 * .setBorder(BorderFactory.createTitledBorder("Choose capture device"
		 * )); adapterPane.setAlignmentX(Component.LEFT_ALIGNMENT);
		 * 
		 * promiscCheck=new JCheckBox("Put into promiscuous mode");
		 * promiscCheck.setSelected(true);
		 * promiscCheck.setAlignmentX(Component.LEFT_ALIGNMENT);
		 * 
		 * filterField=new JTextField(20); //filterField.setMaximumSize(new
		 * Dimension(Short.MAX_VALUE,20)); JPanel filterPane=new JPanel();
		 * filterPane.add(new JLabel("Filter")); filterPane.add(filterField);
		 * filterPane
		 * .setBorder(BorderFactory.createTitledBorder("Capture filter"));
		 * filterPane.setAlignmentX(Component.LEFT_ALIGNMENT);
		 */

		JPanel caplenPane = new JPanel();
		caplenPane.setLayout(new BoxLayout(caplenPane, BoxLayout.Y_AXIS));

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

		caplenPane.setBorder(BorderFactory.createTitledBorder("Select Type"));
		caplenPane.setAlignmentX(Component.RIGHT_ALIGNMENT);

		JPanel caplenPane1 = new JPanel();
		caplenPane1.setLayout(new BoxLayout(caplenPane1, BoxLayout.Y_AXIS));

		wholeCheck1 = new JRadioButton("Normal packet");
		wholeCheck1.setSelected(true);
		wholeCheck1.setActionCommand("Normal");
		wholeCheck1.addActionListener(this);
		headCheck1 = new JRadioButton("Attack packet");
		headCheck1.setActionCommand("Attack");
		headCheck1.addActionListener(this);

		ButtonGroup group1 = new ButtonGroup();
		group1.add(wholeCheck1);
		group1.add(headCheck1);

		caplenPane1.add(wholeCheck1);
		caplenPane1.add(headCheck1);

		caplenPane1.setBorder(BorderFactory.createTitledBorder("Select Type"));
		caplenPane1.setAlignmentX(Component.RIGHT_ALIGNMENT);

		JPanel buttonPane = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		JButton okButton = new JButton("OK");
		okButton.setActionCommand("OK");
		okButton.addActionListener(this);
		JButton cancelButton = new JButton("Cancel");
		cancelButton.setActionCommand("Cancel");
		cancelButton.addActionListener(this);
		buttonPane.add(okButton);
		buttonPane.add(cancelButton);
		buttonPane.setAlignmentX(Component.RIGHT_ALIGNMENT);

		JPanel westPane = new JPanel();

		// westPane.add(Box.createRigidArea(new Dimension(5,5)));
		// westPane.setLayout(new BoxLayout(westPane,BoxLayout.Y_AXIS));
		westPane.add(caplenPane);
		westPane.add(caplenPane1);
		westPane.setLayout(new BoxLayout(westPane, BoxLayout.Y_AXIS));
		westPane.add(Box.createRigidArea(new Dimension(5, 30)));
		westPane.add(buttonPane);
		westPane.add(Box.createRigidArea(new Dimension(5, 5)));

		getContentPane().setLayout(
				new BoxLayout(getContentPane(), BoxLayout.X_AXIS));
		getContentPane().add(Box.createRigidArea(new Dimension(10, 10)));
		getContentPane().add(westPane);
		getContentPane().add(Box.createRigidArea(new Dimension(10, 10)));
		// getContentPane().add(eastPane);
		getContentPane().add(Box.createRigidArea(new Dimension(10, 10)));
		pack();

		// setLocation(parent.getLocation().x+100,parent.getLocation().y+100);
		/*
		 * URL fileurl=null; File file=null; helpfile = new JEditorPane();
		 * helpfile.setEditable(false); helpfile.setContentType("text/html");
		 * try { fileurl = MainGui.class.getResource("README.htm");
		 * helpfile.setPage(fileurl); } catch(IOException ex) {
		 * ex.printStackTrace(); }
		 * 
		 * 
		 * JPanel caplenPane=new JPanel(); caplenPane.setLayout(new
		 * BoxLayout(caplenPane,BoxLayout.Y_AXIS)); caplenField=new
		 * JTextField("1514"); caplenField.setEnabled(false);
		 * caplenField.setMaximumSize(new Dimension(Short.MAX_VALUE,20));
		 * wholeCheck=new JRadioButton("Whole packet");
		 * wholeCheck.setSelected(true); wholeCheck.setActionCommand("Whole");
		 * wholeCheck.addActionListener(this); headCheck=new
		 * JRadioButton("Header only"); headCheck.setActionCommand("Head");
		 * headCheck.addActionListener(this); userCheck=new
		 * JRadioButton("Other"); userCheck.setActionCommand("Other");
		 * userCheck.addActionListener(this); ButtonGroup group=new
		 * ButtonGroup(); group.add(wholeCheck); group.add(headCheck);
		 * group.add(userCheck); caplenPane.add(caplenField);
		 * caplenPane.add(wholeCheck); caplenPane.add(headCheck);
		 * caplenPane.add(userCheck);
		 * caplenPane.setBorder(BorderFactory.createTitledBorder
		 * ("Max capture length"));
		 * caplenPane.setAlignmentX(Component.RIGHT_ALIGNMENT);
		 * getContentPane().add(caplenPane);
		 * 
		 * JPanel buttonPane=new JPanel(new FlowLayout(FlowLayout.RIGHT));
		 * JButton okButton=new JButton("OK"); okButton.setActionCommand("OK");
		 * okButton.addActionListener(this); JButton cancelButton=new
		 * JButton("Cancel"); cancelButton.setActionCommand("Cancel");
		 * cancelButton.addActionListener(this); buttonPane.add(okButton);
		 * buttonPane.add(cancelButton);
		 * buttonPane.setAlignmentX(Component.RIGHT_ALIGNMENT);
		 * getContentPane().add(buttonPane);
		 */
		setDefaultCloseOperation(DISPOSE_ON_CLOSE);
		setVisible(true);
	}

	public int getvalue() {
		return value;
	}

	@Override
	public void actionPerformed(ActionEvent evt) {
		String cmd = evt.getActionCommand();

		if (cmd.equals("Normal")) {
			value = 0;
			// System.out.println(value);

		} else if (cmd.equals("Attack")) {

			value = 1;
			// System.out.println(value);

		} else if (cmd.equals("OK")) {
			value = 3;
			System.out.print("dispose" + value);
			dispose();

		} else if (cmd.equals("Cancel")) {
			dispose();
		}
	}
}
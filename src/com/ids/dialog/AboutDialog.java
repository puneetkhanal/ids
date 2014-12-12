package com.ids.dialog;

import java.awt.*;
import javax.swing.*;

public class AboutDialog extends JDialog {
	private JScrollPane jsp;

	public AboutDialog(JFrame owner) {
		super(owner, "About Intelligent Intrustion Detection");
		int w = 400;
		int h = 300;
		setLocation(w, h);

		Font textFont;
		textFont = new Font("TimesNewRoman", Font.BOLD, 14);
		JTextArea jt = new JTextArea();

		jt.setLineWrap(true);
		jt.setMinimumSize(new Dimension(600, 600));
		jt.setEditable(false);
		jt.setFont(textFont);
		jt.setForeground(Color.black);
		jt.setText("Intelligent Network Intrusion Detection System\n\n");
		jt.append("   INIDS is a software to detect anomaly in packets. It is based on packet header anomaly detection. It uses naive bayes algorithm for classifying normal and attack packets. Packets can be captured \nfrom device as well as well known dump files like(.cap,.pcap,.tcpdump). The probability that a \npacket is normal is displayed. Baesed on the set threshold, packet is classified as normal or attack. Then, the network administrator can take decisions to whether add the packet features to the \ndataset or not.");
		jsp = new JScrollPane(jt);

		// jsp.getViewport().add(helpfile, BorderLayout.CENTER);

		setSize(700, 200);
		getContentPane().add(jsp);
		setDefaultCloseOperation(DISPOSE_ON_CLOSE);
		setVisible(true);
	}
}
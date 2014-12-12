package com.ids;

import javax.swing.JFrame;

public class Intrusion extends JFrame {

	public static void main(String[] args) throws Exception {
		javax.swing.SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				MainGui mg = new MainGui();

				mg.setTitle("Intelligent Network Intrusion Detection");
				mg.setVisible(true);
			}
		}

		);
	}
}
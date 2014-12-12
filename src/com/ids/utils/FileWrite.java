package com.ids.utils;

import java.io.*;

public class FileWrite {
	public void write(String s, int i, boolean value) {
		FileOutputStream out;
		PrintStream p;

		try {
			out = new FileOutputStream("traindata.txt", value);

			p = new PrintStream(out);

			p.println(s);

			p.close();

		} catch (Exception e) {
			System.err.println("Error writing to file");
		}
	}
}

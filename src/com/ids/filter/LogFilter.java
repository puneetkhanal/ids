package com.ids.filter;

import java.io.File;

public class LogFilter extends javax.swing.filechooser.FileFilter {
	private String xtnsn;

	public LogFilter(String str) {
		if (str != null) {
			xtnsn = str;

		} else {
			xtnsn = null;
		}
	}

	/* Is this the file type we care about? Return true on success. */
	@Override
	public boolean accept(File f) {
		if (f.isDirectory()) {
			return true;
		}

		if (getExtension(f).equalsIgnoreCase(xtnsn)) {
			return true;
		}

		return false;
	}

	/* gets the file description. */
	@Override
	public String getDescription() {
		return xtnsn;
	}

	/* gets the file extension */
	private String getExtension(File f) {
		String s = f.getName();
		int i = s.lastIndexOf('.');

		if (i > 0 && i < s.length() - 1) {
			return s.substring(i).toLowerCase();
		}

		return "";
	}

	@Override
	protected void finalize() {
		xtnsn = null;
	}
}
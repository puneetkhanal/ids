package com.ids.bayes;

import smile.learning.*;
import smile.*;

public class Naivebayes {
	public void learn(String s) {
		NaiveBayes naive = new NaiveBayes();
		DataSet D = new DataSet();
		D.readFile(s);
		// System.out.println(D.getVariableCount());
		Network net1 = new Network();
		naive.setClassVariableId("type");
		net1 = naive.learn(D);
		naive.setFeatureSelection(true);
		// System.out.print(naive.getPriorsMethod());
		// System.out.print(naive.getFeatureSelection());
		net1.writeFile("naive.xdsl");
	}

}

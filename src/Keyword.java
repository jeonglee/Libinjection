import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.HashMap;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Keyword {
	HashMap<String, Character> keywordMap = new HashMap<String, Character>();

	public Keyword(String filename) {
		String word;
		char type;
		Pattern wordpattern, typepattern;
		Matcher matchedword, matchedtype;

		try {
			Scanner in = new Scanner(new FileReader(filename));
			String line;
			
			while (in.hasNextLine()) {
				line = in.nextLine();
				wordpattern = Pattern.compile("\\{\"(.*)\"");
				typepattern = Pattern.compile("\'(.*)\'");
				matchedword = wordpattern.matcher(line);
				matchedtype = typepattern.matcher(line);

				while (matchedword.find() && matchedtype.find()) {
					word = matchedword.group(1);
					type = matchedtype.group(1).charAt(0);
					keywordMap.put(word, type);
				}
			}
			in.close();
		} catch (FileNotFoundException ex) {
			System.out.println("file not found");
		}
	}

	void printKeywordMap() {
		for (String keyword : keywordMap.keySet()) {
			String keytype = keywordMap.get(keyword).toString();
			System.out.println("word: " + keyword + " type: " + keytype);
		}
		System.out.println("table size: " + keywordMap.size());
	}
}

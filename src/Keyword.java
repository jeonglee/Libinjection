import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class Keyword {
	HashMap<String, Character> keywordMap = new HashMap<String, Character>();
	int sql_keywords_sz = 0;
	
	public Keyword(String filename) {
		try {
			Scanner in = new Scanner(new FileReader(filename));
			in.useDelimiter("' ");
			while (in.hasNextLine()) {
				System.out.println(in.next());
				
				sql_keywords_sz++;
			}
			System.out.println(sql_keywords_sz);
			
		}
		catch (FileNotFoundException ex) {
			System.out.println("file not found");
		}
	}	
}

import java.io.File;

public class Main {

	public static void main(String[] args) {
		String input = "admin";
		State state = new State(input, input.length(), 0);
//		System.out.println(new File(".").getAbsoluteFile());
//		Keyword map = new Keyword("/Users/Qubit/Documents/workspace/Libinjection/src/Keywords.txt");
//		map.printKeywordMap();
//      System.out.println(map.keywordMap.get("0SO1L"));
		
		Libinjection test = new Libinjection();
		System.out.println(test.libinjection_sqli("{}};(),"));

	}

}

import java.io.File;

public class Main {

	public static void main(String[] args) {
		String input = "admin";
		State state = new State(input, input.length(), 0);
		Keyword map = new Keyword("/Users/Qubit/Documents/workspace/Libinjection/src/Keywords.txt");
		Libinjection test = new Libinjection();

		
//		System.out.println(new File(".").getAbsoluteFile());
//		map.printKeywordMap();
		

//		
//		System.out.println(test.libinjection_sqli("{}};(),"));		
		state.fingerprint = "abcdefghijklmnopqrstuvwxyzABCDEF";
		test.libinjection_sqli_blacklist(state);
		
//		map.printKeywordMap();
		
		

	}

}

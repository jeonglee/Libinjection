import java.util.Arrays;

public class Main {

	public static void main(String[] args) {
		String input = "admin";
		State state = new State(input, input.length(), 0);
		Keyword map = new Keyword("bin/Keywords.txt");
		Libinjection libinjection = new Libinjection();

		//System.out.println(map.keywordMap.get("0N&1"));

		
		//Test test = new Test("src/sqli-all.txt.decoded");
		libinjection.libinjection_sqli("1+UnIoN/**/SeLecT/**/1,2,3--");
		
//		boolean issqli = test.libinjection_sqli("admin' OR 1=1--");
//		System.out.println(issqli);
		
//		String s = "blah";
//		System.out.println(s.substring(2,4));
		
//		String[] as = {
//			" ", "[","]","{","}","<",">",":","\\","?","=","@","!","#","~","+","-","*","/","&","|","^","%",
//			"(",")","'",";","\t","\n","\\v","\f","\r","\"","\240","\000"
//		};
//		
//		String[] samples = {
//			"abc",
//			"[",
//			"[[",
//			"]",
//			"def"
//		};
	
//		StringBuffer sb = new StringBuffer();
//		sb.append("[");
//		for(String s : as) {
//			sb.append( Pattern.quote( s ) );
//			System.out.println(Pattern.quote(s));
//		}
//		sb.append("]*");
//		String regexp = sb.toString();
//		
//		Pattern pattern = Pattern.compile( regexp);
//		
////		for(String sample : samples) {
////			
////			System.out.println("");
////			System.out.println( sample);
////			
////			matcher = pattern.matcher( sample );
////			
////			if ( matcher.matches()) {
////				System.out.println("--- MATCHES: yes----");
////				System.out.println(matcher.groupCount());			
////			}
////			else {
////				System.out.println("--- MATCHES: no----");
////			}
////		}
		
	}
}

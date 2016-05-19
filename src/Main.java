
public class Main {

	public static void main(String[] args) {
//		Libinjection libinjection = new Libinjection();
//		libinjection.libinjection_sqli("admin' OR 1=1--");
		
		Test t = new Test();
		t.testfile("src/sqli-all.txt", "src/sqli-all.txt.output", true, false);
	}
}

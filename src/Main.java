
public class Main {

	public static void main(String[] args) {
		Libinjection a = new Libinjection();
		boolean issqli = a.libinjection_sqli("admin' OR 1=1--");
		System.out.println(issqli);
		
		Test t = new Test();
		t.testfile("src/sqli-all.txt", "src/sqli-all.txt.output", true, false);
	}
}

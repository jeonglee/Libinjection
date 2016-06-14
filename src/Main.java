
public class Main {

	public static void main(String[] args) {
		/* test a string */
		Libinjection a = new Libinjection();
		boolean issqli = a.libinjection_sqli("admin' OR 1=1--");
		System.out.println(issqli);

		/* test a file and output its results, with options to urldecode and time */
		Test t = new Test();
		t.testfile("data/sqli.txt", "data/sqli.txt.output", true, false);


		/* performance test */
//		Libinjection b = new Libinjection();
//		String[] test = {
//				"123 LIKE -1234.5678E+2;",
//				"APPLE 19.123 'FOO' \"BAR\"",
//				"/* BAR */ UNION ALL SELECT (2,3,4)",
//				"1 || COS(+0X04) --FOOBAR",
//				"dog apple @cat banana bar",
//				"dog apple cat \"banana \'bar",
//				"102 TABLE CLOTH",
//				"(1001-'1') union select 1,2,3,4 from credit_cards"
//		};
//
//		/* print output for above inputs */
//		for (int i = 0 ; i < test.length; i++) {
//			b.libinjection_sqli(test[i]);
//			System.out.println(b.getOutput());
//		}
//
//		/* let jvm optimize for 100000 iterations */
//		for (int c = 0; c < 100000; c++) {
//			b.libinjection_sqli(test[c % 8]);
//		}
//
//		/* time */
//		double start = System.currentTimeMillis();
//		for (int c = 0; c < 1000000; c++) {
//			b.libinjection_sqli(test[c % 8]);
//		}
//		double end   = System.currentTimeMillis();
//
//		double total = (end - start) / 1000.0;
//		double tps = 1000000.0 / total;
//		System.out.println("iterations: " + 10000000 + "\ntotal time: " + total +" sec");
//		System.out.println((int) tps + " / sec");
	}
}

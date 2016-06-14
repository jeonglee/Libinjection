
public class Main {

	public static void main(String[] args) {
//		Libinjection a = new Libinjection();
//		boolean issqli = a.libinjection_sqli("admin' OR 1=1--");
//		System.out.println(issqli);
//
//		Test t = new Test();
//		long sum = 0;
//		long count = 1000;
//		while (count-- > 0) {
//			sum += t.testfile("src/sqli-all.txt", "src/sqli-all.txt.output", true, true);
//		}
//		System.out.println(sum/1000);


		Libinjection b = new Libinjection();
		String[] test = {
				"123 LIKE -1234.5678E+2;",
				"APPLE 19.123 'FOO' \"BAR\"",
				"/* BAR */ UNION ALL SELECT (2,3,4)",
				"1 || COS(+0X04) --FOOBAR",
				"dog apple @cat banana bar",
				"dog apple cat \"banana \'bar",
				"102 TABLE CLOTH",
				"(1001-'1') union select 1,2,3,4 from credit_cards"
		};

		int iterations = 1000000;
		int i = 0;

		for (int c=0; c<iterations; c++) {
			if (i == 8) {
				i = 0;
			}
			String curr = test[i];
			b.libinjection_sqli(test[i]);
			System.out.println(b.getOutput() + " " + b.getState().fingerprint);
			i++;
		}

		double start = System.currentTimeMillis();
		for (int c=0; c<iterations; c++) {
			if (i == 8) {
				i = 0;
			}
			String curr = test[i];
			b.libinjection_sqli(test[i]);
			i++;
		}

		double end = System.currentTimeMillis();
		double total = (end - start) / 1000.0;
		double tps = (double) 1000000 / total;
		System.out.println("iterations: " + iterations + " total time: " + total);
		System.out.println((int) tps + "/second");
	}
}

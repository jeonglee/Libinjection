
public class Main {

	public static void main(String[] args) {
		long start;
		long end;
		long time;
		
		Libinjection libinjection = new Libinjection();
		libinjection.libinjection_sqli("admin' OR 1=1--");
		
//		start = System.currentTimeMillis();
//		Libinjection libinjection = new Libinjection();
//		end = System.currentTimeMillis();
//		time = end - start;
//		System.out.println(time);
//		
//		start = System.currentTimeMillis();
//		libinjection.libinjection_sqli("admin' OR 1=1--");
//		end = System.currentTimeMillis();
//		System.out.println(end - start);
		
//		Test test = new Test();
//		System.out.println(test.testfile("src/sqli-all.txt", "src/sqli-all.txt.output", false, true));
		
//		Test t = new Test();
//		long totaltime = 0;
//		int i = 0;
//		while (i < 1000) {
//			totaltime += t.testfile("src/sqli-all.txt", "src/sqli-all.txt.output", true, true);
//			i++;
//		}
//		System.out.println(totaltime/i);
		
//		Test fpos = new Test();
//		fpos.testfile(", outputfile, decode);
	}
}

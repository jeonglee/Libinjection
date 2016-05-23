# Libinjection - Java
This is a porting of the SQLi detection tool [libinjection](https://github.com/client9/libinjection) to Java.



```Java
public class Main {

	public static void main(String[] args) {
	/* test a string */
		Libinjection libinjection = new Libinjection();
		libinjection.libinjection_sqli("admin' OR 1=1--");
	
	/* test a file, with options to urldecode and time execution (in milliseconds) */ 	
		Test t = new Test();
		t.testfile("src/sqli-all.txt", "src/sqli-all.txt.output", true, false);
	}
}
```

So far it's been tested on around 85,000 SQLi input collected from the original libinjection library [here](https://github.com/client9/libinjection/tree/master/data),
with results matching those of the original libinjection.

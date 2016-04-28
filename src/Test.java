import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Scanner;


public class Test {
	public Test(String filename) {
		Scanner in = null;
		PrintWriter out = null;
		int count = 0;
		try {
			in = new Scanner(new FileReader(filename));
			out =  new PrintWriter("src/sqli-all.java.results", "UTF-8");
			String line;
			Libinjection libinjection = new Libinjection();
			while (in.hasNextLine()) {
				line = in.nextLine();
				// urldecode
				try {
					line = URLDecoder.decode(line, "UTF-8");
				} catch (UnsupportedEncodingException ex) {
					ex.printStackTrace();
				}
				
				libinjection.libinjection_sqli(line);
				//System.out.println(++count);
				out.println(libinjection.output);
			}
			in.close();
		} catch (FileNotFoundException | UnsupportedEncodingException ex) {
			System.out.println("file not found");
		} finally {
			if (in != null) {
				try {
					in.close();
					in = null;
				} catch(Exception ex3) { ex3.printStackTrace(); }
			}
			if (out != null) {
				try {
					out.close();
					out = null;
				} catch(Exception ex3) { ex3.printStackTrace(); }
			}
			
		}
	}

}

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Scanner;


public class Test {
	public void testfile(String inputfile, String outputfile) {
		Scanner in = null;
		PrintWriter out = null;
		
		try {
			in = new Scanner(new FileReader(inputfile));
			out =  new PrintWriter(outputfile, "UTF-8");
			Libinjection libinjection = new Libinjection();
			
			while (in.hasNextLine()) {
				String line = in.nextLine();
				
				/* 
				 * urldecode
				 */
				try {
					line = URLDecoder.decode(line, "UTF-8");
				} catch (UnsupportedEncodingException ex) {
					ex.printStackTrace();
				}
				
				/*
				 *  test and add result to outputfile
				 */
				libinjection.libinjection_sqli(line);
				out.println(libinjection.getOutput());
			}
		} catch (FileNotFoundException | UnsupportedEncodingException ex) {
			System.out.println("file not found or unsupported encoding");
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

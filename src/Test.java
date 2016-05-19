import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Scanner;


public class Test {
	public long testfile(String inputfile, String outputfile, boolean decode, boolean time) {
		long startTime;
		long endTime;
		long sum = 0;
		int count = 0;
		
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
				if (decode) {
					try {
						line = URLDecoder.decode(line, "UTF-8");
					} catch (UnsupportedEncodingException ex) {
					ex.printStackTrace();
					}
				}
				
				/*
				 *  test and add result to outputfile
				 */
				if (time) { 
					startTime = System.currentTimeMillis(); 
					libinjection.libinjection_sqli(line);
					endTime = System.currentTimeMillis();
					sum += (endTime - startTime);
					count++;
				} else {
					libinjection.libinjection_sqli(line);
				}
				
				out.println(libinjection.getOutput());
			}
			if (time) {
				System.out.println("Total: " + sum + " Average: " + sum/count);
			}
			return sum;
			
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
		return Integer.MIN_VALUE;
	}

}

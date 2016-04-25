
public class State {
	
	String s;	// input string
	int slen;	// length of input
	int fplen;	// length of fingerprint
	int flags;	// flag to indicate which mode we're running in: example.) flag_quote_none AND flag_sql_ansi 
	int pos;  	// index in string during tokenization
	Token[] tokenvec = new Token[8];
	int current; // current position in tokenvec
	String fingerprint;
	int reason;
    int stats_comment_ddw;
	int stats_comment_ddx;
    int stats_comment_c;	//c-style comments found  /x .. x/
    int stats_comment_hash;	//'#' operators or MySQL EOL comments found
    int stats_folds;
    int stats_tokens;		
	// ptr_looup_fn lookup; ==> lookup function
	// void* userdata; ==> pointer to userdata
    
    
    
    public State(String s, int len, int flags) {
    	if (flags == 0) {
    		flags = Libinjection.FLAG_QUOTE_NONE | Libinjection.FLAG_SQL_ANSI;
    	}
 
    	this.s = s;
    	this.slen = len;
        this.flags = flags;
        this.current = 0;    
//    	sf->lookup = libinjection_sqli_lookup_word;
//      sf->userdata = 0;
    }
    
    
    
    void printState() {
    	System.out.printf("Input: %s\n", s);
    	System.out.printf("Length: %d\n", slen);
    	System.out.printf("Flags: %d\n",  flags);
    	System.out.printf("Position in input string: %d\n", pos);
    	System.out.printf("Current token index: %d\n", current);
    	System.out.println("Tokenvec:");
    	if (tokenvec != null) {
    		int i = 0;
    		while (tokenvec[i] != null) {
    			System.out.printf("[%s ", tokenvec[i].type);
    		System.out.printf("%s] \n", tokenvec[i].val);
    			i++;
    		}
    		System.out.println();
    	}
    }
}

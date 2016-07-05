
class Token {
	char type;
	char str_open;
	char str_close;
	String val;
	int count;
	// position and length of input in original string
	int pos; 
	int len;
	
	Token(int stype, int pos, int len, String val) {
		this.type = (char) stype;
		this.pos = pos;
		this.len = len;
		this.val = val;
	}
	
	void printToken() {
		System.out.printf("Token represents %s\n", val);
		System.out.printf("Type:         %c\n", type);
		System.out.printf("Position:     %d\n", pos);
		System.out.printf("Length:       %d\n", len);
		System.out.printf("Number of '@': %d\n", count);
		System.out.printf("String open:  %c\n", str_open);
		System.out.printf("String close: %c\n", str_close);
	}
}

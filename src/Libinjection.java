
public class Libinjection {

	public static final int LIBINJECTION_SQLI_MAX_TOKENS = 5;

	public static final int FLAG_QUOTE_NONE = 1 /* 1 << 0 */
			, FLAG_QUOTE_SINGLE = 2 /* 1 << 1 */
			, FLAG_QUOTE_DOUBLE = 4 /* 1 << 2 */
			, FLAG_SQL_ANSI = 8 /* 1 << 3 */
			, FLAG_SQL_MYSQL = 16; /* 1 << 4 */

	public static final int LOOKUP_WORD = 1, LOOKUP_TYPE = 2, LOOKUP_OPERATOR = 3, LOOKUP_FINGERPRINT = 4;

	public static final char CHAR_NULL = '\0', CHAR_SINGLE = '\'', CHAR_DOUBLE = '"', CHAR_TICK = '`';

	public static final int TYPE_NONE = 0, TYPE_KEYWORD = (int) 'k', TYPE_UNION = (int) 'U', TYPE_GROUP = (int) 'B',
			TYPE_EXPRESSION = (int) 'E', TYPE_SQLTYPE = (int) 't', TYPE_FUNCTION = (int) 'f', TYPE_BAREWORD = (int) 'n',
			TYPE_NUMBER = (int) '1', TYPE_VARIABLE = (int) 'v', TYPE_STRING = (int) 's', TYPE_OPERATOR = (int) 'o',
			TYPE_LOGIC_OPERATOR = (int) '&', TYPE_COMMENT = (int) 'c', TYPE_COLLATE = (int) 'A',
			TYPE_LEFTPARENS = (int) '(', TYPE_RIGHTPARENS = (int) ')', TYPE_LEFTBRACE = (int) '{',
			TYPE_RIGHTBRACE = (int) '}', TYPE_DOT = (int) '.', TYPE_COMMA = (int) ',', TYPE_COLON = (int) ':',
			TYPE_SEMICOLON = (int) ';', TYPE_TSQL = (int) 'T', TYPE_UNKNOWN = (int) '?', TYPE_EVIL = (int) 'X',
			TYPE_FINGERPRINT = (int) 'F', TYPE_BACKSLASH = (int) '\\';

	public static final int TRUE = 1, FALSE = 0;

	Keyword keywords = new Keyword("/Users/Qubit/Documents/workspace/Libinjection/src/Keywords.txt");

	/* Main API */
	boolean libinjection_sqli(String input) {
		State state = new State(input, input.length(), 0);
		return libinjection_is_sqli(state) == TRUE;
	}

	int libinjection_is_sqli(State state) {
		String s = state.s;
		int slen = state.slen;

		// if no input, not SQLi
		if (slen == 0) {
			return FALSE;
		}

		// test input "as-is". Does tokenizing and folding to get a fingerprint
		// of input.
		libinjection_sqli_fingerprint(state, FLAG_QUOTE_NONE | FLAG_SQL_ANSI);
		boolean sqlifingerprint = libinjection_sqli_check_fingerprint(state);
		if (sqlifingerprint) {
			return TRUE;
		} else if (reparse_as_mysql(state)) {
			libinjection_sqli_fingerprint(state, FLAG_QUOTE_NONE | FLAG_SQL_MYSQL);
			sqlifingerprint = libinjection_sqli_check_fingerprint(state);
			if (sqlifingerprint) {
				return TRUE;
			}
		}

		return FALSE;
	}

	boolean reparse_as_mysql(State state) {
		return (state.stats_comment_ddx + state.stats_comment_hash) > 0;
	}

	/* Secondary API: Detect SQLi GIVEN a context. */
	String libinjection_sqli_fingerprint(State state, int flags) {
		int i;
		int fplen = 0;
		String fp = "";

		// sqli_reset(state, flags) --> didn't implement. dunno why it's needed

		// tokenize and fold
		fplen = libinjection_sqli_fold(state);

		// copy tokenvec to fingerprint
		for (i = 0; i < fplen; i++) {
			fp = fp + state.tokenvec[i].type;
		}
		state.fingerprint = fp;

		return state.fingerprint;

	}

	Character libinjection_sqli_lookup_word(String str) {
		return keywords.keywordMap.get(str);
	}

	boolean is_keyword(String str) {
		Character value = keywords.keywordMap.get(str);
		if (value == null || value != TYPE_FINGERPRINT) {
			return false;
		}
		return true;
	}

	boolean libinjection_sqli_check_fingerprint(State state) {
		return libinjection_sqli_blacklist(state);
	}

	boolean libinjection_sqli_blacklist(State state) {
		int len = state.fingerprint.length();
		boolean patmatch;
		int ascii;
		String fp2 = "0";

		if (len < 1) {
			System.out.println("blacklisted: fingerprint length < 1");
			return false;
		}

		// maybe just use fp2.toUpperCase()?
		for (int i = 0; i < len; i++) {
			ascii = (int) state.fingerprint.charAt(i);
			if (ascii > 0x60 && ascii < 0x7B) {
				ascii -= 0x20;
			}
			fp2 = fp2 + (char) ascii;
		}

		patmatch = is_keyword(fp2);
		if (!patmatch) {
			System.out.printf("fingerprint: %s not in blacklist\n", fp2);
			return false;
		}

		System.out.printf("fingerprint: %s found in blacklist\n", fp2);
		return true;
	}

	// Returns the number of tokens in final fingerprint.
	int libinjection_sqli_fold(State state) {
		/* UNFINISHED */
		int pos = 0; // position where NEXT token goes
		int left = 0; // count of how many tokens that are already folded or
						// processed (i.e. part of the fingerprint)
		int current = state.current;
		boolean more = true;
		/*
		 * A comment token to add additional information. Initialized to prevent
		 * errors
		 */
		Token last_comment = new Token(CHAR_NULL, 0, 0, null);

		while (more) {
			more = libinjection_sqli_tokenize(state);
			if (!(state.tokenvec[current].type == TYPE_COMMENT || state.tokenvec[current].type == TYPE_LEFTPARENS
					|| state.tokenvec[current].type == TYPE_SQLTYPE || token_is_unary_op(state.tokenvec[current]))) {
				break;
			}
		}

		if (!more) {
			return 0;
		} else {
			pos += 1;
		}

		while (true) {
			/*
			 * do we have all the max number of tokens? if so do some special
			 * cases for 5 tokens
			 */
			if (pos >= LIBINJECTION_SQLI_MAX_TOKENS) {

			}

			// if processed all characters in input or the number of tokens in
			// fingerprint exceeds 5, stop.
			if (!more || left >= LIBINJECTION_SQLI_MAX_TOKENS) {
				left = pos;
				break;
			}

			// get up to two tokens (assuming pos == left)
			while (more && pos <= LIBINJECTION_SQLI_MAX_TOKENS && (pos - left) < 2) {
				state.current = pos;
				more = libinjection_sqli_tokenize(state);
				if (more) {
					if (state.tokenvec[current].type == TYPE_COMMENT) {
						last_comment = state.tokenvec[current];
					} else {
						last_comment.type = CHAR_NULL;
						pos += 1;
					}
				}
			}

			/*
			 * if we didn't get at least two tokens, it means we exited above
			 * while loop because we: 1.) processed all of the input OR 2.)
			 * added the 5th (and last) token In this case go through loop
			 * again, go through special cases, exit or keep going.
			 */
			if (pos - left < 2) {
				left = pos;
				continue;
			}

			/*
			 * two token folding
			 */
			if (state.tokenvec[left].type == TYPE_STRING && state.tokenvec[left+1].type == TYPE_STRING) {
				pos -= 1;
				state.stats_folds += 1;
				continue;
			} else if (state.tokenvec[left].type == TYPE_SEMICOLON && state.tokenvec[left+1].type == TYPE_SEMICOLON) {
				// fold away repeated semicolons. i.e. ;; to ;
				pos -= 1;
				state.stats_folds += 1;
				continue;
			} else if (state.tokenvec[left].type == TYPE_SEMICOLON  &&
					state.tokenvec[left+1].type == TYPE_FUNCTION &&
					state.tokenvec[left+1].val.toUpperCase().equals("IF")) {
				state.tokenvec[left+1].type = TYPE_TSQL;
				left += 2;
				continue; // reparse everything. but we probably can advance left, and pos */
	        } else if ((state.tokenvec[left].type == TYPE_OPERATOR ||
                    state.tokenvec[left].type == TYPE_LOGIC_OPERATOR) &&
                   (token_is_unary_op(state.tokenvec[left+1]) ||
                    state.tokenvec[left+1].type == TYPE_SQLTYPE)) {
	        	pos -= 1;
	        	state.stats_folds += 1;
	        	left = 0;
	        	continue;
	        } else if (state.tokenvec[left].type == TYPE_LEFTPARENS &&
	                   token_is_unary_op(state.tokenvec[left+1])) {
	            pos -= 1;
	            state.stats_folds += 1;
	            if (left > 0) {
	                left -= 1;
	            }
	            continue;
	        } else if (syntax_merge_words(state, state.tokenvec[left], left, state.tokenvec[left+1], left+1)) {
	            pos -= 1;
	            state.stats_folds += 1;
	            if (left > 0) {
	                left -= 1;
	            }
	            continue;
	        } 
/*  ----------------------------------------------two token handling. take a deeper look--------------------------------------------------------------*/
	        else if ((state.tokenvec[left].type == TYPE_BAREWORD || state.tokenvec[left].type == TYPE_VARIABLE) &&
	                   state.tokenvec[left+1].type == TYPE_LEFTPARENS && (
	                       /* TSQL functions but common enough to be column names */
	                	   state.tokenvec[left].val.toUpperCase().equals("USER_ID") ||
	                	   state.tokenvec[left].val.toUpperCase().equals("USER_NAME") ||

	                       /* Function in MYSQL */
	                	   state.tokenvec[left].val.toUpperCase().equals("DATABASE") ||
	                	   state.tokenvec[left].val.toUpperCase().equals("PASSWORD") ||
	                	   state.tokenvec[left].val.toUpperCase().equals("USER") ||

	                       /* Mysql words that act as a variable and are a function */

	                       /* TSQL current_users is fake-variable */
	                       /* http://msdn.microsoft.com/en-us/library/ms176050.aspx */
	                	   state.tokenvec[left].val.toUpperCase().equals("CURRENT_USER") ||
	                	   state.tokenvec[left].val.toUpperCase().equals("CURRENT_DATE") ||
	                	   state.tokenvec[left].val.toUpperCase().equals("CURRENT_TIME") ||
	                	   state.tokenvec[left].val.toUpperCase().equals("CURRENT_TIMESTAMP") ||
	                	   state.tokenvec[left].val.toUpperCase().equals("LOCALTIME") ||
	                	   state.tokenvec[left].val.toUpperCase().equals("LOCALTIMESTAMP")
	                       )) {

	            /* pos is the same
	             * other conversions need to go here... for instance
	             * password CAN be a function, coalesce CAN be a function
	             */
	            state.tokenvec[left].type = TYPE_FUNCTION;
	            continue;
	        } else if (state.tokenvec[left].type == TYPE_KEYWORD && (
	        		state.tokenvec[left].val.toUpperCase().equals("IN") ||
	        		state.tokenvec[left].val.toUpperCase().equals("NOT IN")
	                       )) {

	            if (state.tokenvec[left+1].type == TYPE_LEFTPARENS) {
	                /* got .... IN ( ...  (or 'NOT IN')
	                 * it's an operator
	                 */
	                state.tokenvec[left].type = TYPE_OPERATOR;
	            } else {
	                /*
	                 * it's a nothing
	                 */
	                state.tokenvec[left].type = TYPE_BAREWORD;
	            }

	            /* "IN" can be used as "IN BOOLEAN MODE" for mysql
	             *  in which case merging of words can be done later
	             * other wise it acts as an equality operator __ IN (values..)
	             *
	             * here we got "IN" "(" so it's an operator.
	             * also back track to handle "NOT IN"
	             * might need to do the same with like
	             * two use cases   "foo" LIKE "BAR" (normal operator)
	             *  "foo" = LIKE(1,2)
	             */
	            continue;
	        } else if ((state.tokenvec[left].type == TYPE_OPERATOR) && (
	        		state.tokenvec[left].val.toUpperCase().equals("LIKE") ||
	        		state.tokenvec[left].val.toUpperCase().equals("NOT LIKE"))) {
	            if (state.tokenvec[left+1].type == TYPE_LEFTPARENS) {
	                /* SELECT LIKE(...
	                 * it's a function
	                 */
	                state.tokenvec[left].type = TYPE_FUNCTION;
	            }
	        } else if (state.tokenvec[left].type == TYPE_SQLTYPE &&
	                   (state.tokenvec[left+1].type == TYPE_BAREWORD ||
	                    state.tokenvec[left+1].type == TYPE_NUMBER ||
	                    state.tokenvec[left+1].type == TYPE_SQLTYPE ||
	                    state.tokenvec[left+1].type == TYPE_LEFTPARENS ||
	                    state.tokenvec[left+1].type == TYPE_FUNCTION ||
	                    state.tokenvec[left+1].type == TYPE_VARIABLE ||
	                    state.tokenvec[left+1].type == TYPE_STRING))  {
	            //st_copy(&state.tokenvec[left], &state.tokenvec[left+1]);
	        	state.tokenvec[left] = state.tokenvec[left+1];
	            pos -= 1;
	            state.stats_folds += 1;
	            left = 0;
	            continue;
	        } else if (state.tokenvec[left].type == TYPE_COLLATE &&
	                   state.tokenvec[left+1].type == TYPE_BAREWORD) {
	            /*
	             * there are too many collation types.. so if the bareword has a "_"
	             * then it's TYPE_SQLTYPE
	             */
	            //if (strchr(state.tokenvec[left+1].val, '_') != NULL) {
	        	if (state.tokenvec[left+1].val.indexOf('_') != -1) {
	                state.tokenvec[left+1].type = TYPE_SQLTYPE;
	                left = 0;
	            }
	        } else if (state.tokenvec[left].type == TYPE_BACKSLASH) {
	            if (token_is_arithmetic_op(state.tokenvec[left+1])) {
	                /* very weird case in TSQL where '\%1' is parsed as '0 % 1', etc */
	                state.tokenvec[left].type = TYPE_NUMBER;
	            } else {
	                /* just ignore it.. Again T-SQL seems to parse \1 as "1" */
	                //st_copy(&state.tokenvec[left], &state.tokenvec[left+1]);
	            	state.tokenvec[left] = state.tokenvec[left+1];
	                pos -= 1;
	                state.stats_folds += 1;
	            }
	            left = 0;
	            continue;
	        } else if (state.tokenvec[left].type == TYPE_LEFTPARENS &&
	                   state.tokenvec[left+1].type == TYPE_LEFTPARENS) {
	            pos -= 1;
	            left = 0;
	            state.stats_folds += 1;
	            continue;
	        } else if (state.tokenvec[left].type == TYPE_RIGHTPARENS &&
	                   state.tokenvec[left+1].type == TYPE_RIGHTPARENS) {
	            pos -= 1;
	            left = 0;
	            state.stats_folds += 1;
	            continue;
	        } else if (state.tokenvec[left].type == TYPE_LEFTBRACE &&
	                   state.tokenvec[left+1].type == TYPE_BAREWORD) {

	            /*
	             * MySQL Degenerate case --
	             *
	             *   select { ``.``.id };  -- valid !!!
	             *   select { ``.``.``.id };  -- invalid
	             *   select ``.``.id; -- invalid
	             *   select { ``.id }; -- invalid
	             *
	             * so it appears {``.``.id} is a magic case
	             * I suspect this is "current database, current table, field id"
	             *
	             * The folding code can't look at more than 3 tokens, and
	             * I don't want to make two passes.
	             *
	             * Since "{ ``" so rare, we are just going to blacklist it.
	             *
	             * Highly likely this will need revisiting!
	             *
	             * CREDIT @rsalgado 2013-11-25
	             */
	            if (state.tokenvec[left+1].len == 0) {
	                state.tokenvec[left+1].type = TYPE_EVIL;
	                return (int)(left+2);
	            }
	            /* weird ODBC / MYSQL  {foo expr} --> expr
	             * but for this rule we just strip away the "{ foo" part
	             */
	            left = 0;
	            pos -= 2;
	            state.stats_folds += 2;
	            continue;
	        } else if (state.tokenvec[left+1].type == TYPE_RIGHTBRACE) {
	            pos -= 1;
	            left = 0;
	            state.stats_folds += 1;
	            continue;
	        }

	        
/* --------------------------------------------------------------------------------------*/

			/*
			 * all cases of handling 2 tokens is done and nothing matched. Get
			 * one more token
			 */
			while (more && pos <= LIBINJECTION_SQLI_MAX_TOKENS && (pos - left) < 3) {
				state.current = pos;
				more = libinjection_sqli_tokenize(state);
				if (more) {
					if (state.tokenvec[current].type == TYPE_COMMENT) {
						last_comment = state.tokenvec[current];
					} else {
						last_comment.type = CHAR_NULL;
						pos += 1;
					}
				}
			}

			/*
			 * if we didn't get at least three tokens, it means we exited above
			 * while loop because we: 1.) processed all of the input OR 2.)
			 * added the 5th (and last) token In this case go through loop
			 * again, go through special cases, exit or keep going.
			 */
			if (pos - left < 3) {
				left = pos;
				continue;
			}

/* ------------------------------------------------Three token folding. Take a deeper look   -------------------------------------------*/
			
	        if (state.tokenvec[left].type == TYPE_NUMBER &&
	                state.tokenvec[left+1].type == TYPE_OPERATOR &&
	                state.tokenvec[left+2].type == TYPE_NUMBER) {
	                pos -= 2;
	                left = 0;
	                continue;
	            } else if (state.tokenvec[left].type == TYPE_OPERATOR &&
	                       state.tokenvec[left+1].type != TYPE_LEFTPARENS &&
	                       state.tokenvec[left+2].type == TYPE_OPERATOR) {
	                left = 0;
	                pos -= 2;
	                continue;
	            } else if (state.tokenvec[left].type == TYPE_LOGIC_OPERATOR &&
	                       state.tokenvec[left+2].type == TYPE_LOGIC_OPERATOR) {
	                pos -= 2;
	                left = 0;
	                continue;
	            } else if (state.tokenvec[left].type == TYPE_VARIABLE &&
	                       state.tokenvec[left+1].type == TYPE_OPERATOR &&
	                       (state.tokenvec[left+2].type == TYPE_VARIABLE ||
	                        state.tokenvec[left+2].type == TYPE_NUMBER ||
	                        state.tokenvec[left+2].type == TYPE_BAREWORD)) {
	                pos -= 2;
	                left = 0;
	                continue;
	            } else if ((state.tokenvec[left].type == TYPE_BAREWORD ||
	                        state.tokenvec[left].type == TYPE_NUMBER ) &&
	                       state.tokenvec[left+1].type == TYPE_OPERATOR &&
	                       (state.tokenvec[left+2].type == TYPE_NUMBER ||
	                        state.tokenvec[left+2].type == TYPE_BAREWORD)) {
	                pos -= 2;
	                left = 0;
	                continue;
	            } else if ((state.tokenvec[left].type == TYPE_BAREWORD ||
	                        state.tokenvec[left].type == TYPE_NUMBER ||
	                        state.tokenvec[left].type == TYPE_VARIABLE ||
	                        state.tokenvec[left].type == TYPE_STRING) &&
	                       state.tokenvec[left+1].type == TYPE_OPERATOR &&
	                       //streq(state.tokenvec[left+1].val, "::") &&
	                       state.tokenvec[left+1].val.equals("::") &&
	                       state.tokenvec[left+2].type == TYPE_SQLTYPE) {
	                pos -= 2;
	                left = 0;
	                state.stats_folds += 2;
	                continue;
	            } else if ((state.tokenvec[left].type == TYPE_BAREWORD ||
	                        state.tokenvec[left].type == TYPE_NUMBER ||
	                        state.tokenvec[left].type == TYPE_STRING ||
	                        state.tokenvec[left].type == TYPE_VARIABLE) &&
	                       state.tokenvec[left+1].type == TYPE_COMMA &&
	                       (state.tokenvec[left+2].type == TYPE_NUMBER ||
	                        state.tokenvec[left+2].type == TYPE_BAREWORD ||
	                        state.tokenvec[left+2].type == TYPE_STRING ||
	                        state.tokenvec[left+2].type == TYPE_VARIABLE)) {
	                pos -= 2;
	                left = 0;
	                continue;
	            } else if ((state.tokenvec[left].type == TYPE_EXPRESSION ||
	                        state.tokenvec[left].type == TYPE_GROUP ||
	                        state.tokenvec[left].type == TYPE_COMMA) &&
	                       token_is_unary_op(state.tokenvec[left+1]) &&
	                       state.tokenvec[left+2].type == TYPE_LEFTPARENS) {
	                /* got something like SELECT + (, LIMIT + (
	                 * remove unary operator
	                 */
	                //st_copy(&state.tokenvec[left+1], &state.tokenvec[left+2]);
	            	state.tokenvec[left+1] = state.tokenvec[left+2];
	                pos -= 1;
	                left = 0;
	                continue;
	            } else if ((state.tokenvec[left].type == TYPE_KEYWORD ||
	                        state.tokenvec[left].type == TYPE_EXPRESSION ||
	                        state.tokenvec[left].type == TYPE_GROUP )  &&
	                       token_is_unary_op(state.tokenvec[left+1]) &&
	                       (state.tokenvec[left+2].type == TYPE_NUMBER ||
	                        state.tokenvec[left+2].type == TYPE_BAREWORD ||
	                        state.tokenvec[left+2].type == TYPE_VARIABLE ||
	                        state.tokenvec[left+2].type == TYPE_STRING ||
	                        state.tokenvec[left+2].type == TYPE_FUNCTION )) {
	                /* remove unary operators
	                 * select - 1
	                 */
	                //st_copy(&state.tokenvec[left+1], &state.tokenvec[left+2]);
	            	state.tokenvec[left+1] = state.tokenvec[left+2];
	                pos -= 1;
	                left = 0;
	                continue;
	            } else if (state.tokenvec[left].type == TYPE_COMMA &&
	                       token_is_unary_op(state.tokenvec[left+1]) &&
	                       (state.tokenvec[left+2].type == TYPE_NUMBER ||
	                        state.tokenvec[left+2].type == TYPE_BAREWORD ||
	                        state.tokenvec[left+2].type == TYPE_VARIABLE ||
	                        state.tokenvec[left+2].type == TYPE_STRING)) {
	                /*
	                 * interesting case    turn ", -1"  ->> ",1" PLUS we need to back up
	                 * one token if possible to see if more folding can be done
	                 * "1,-1" --> "1"
	                 */
	                //st_copy(&state.tokenvec[left+1], &state.tokenvec[left+2]);
	            	state.tokenvec[left+1] = state.tokenvec[left+2];
	                left = 0;
	                /* pos is >= 3 so this is safe */
	                assert(pos >= 3);
	                pos -= 3;
	                continue;
	            } else if (state.tokenvec[left].type == TYPE_COMMA &&
	                       token_is_unary_op(state.tokenvec[left+1]) &&
	                       state.tokenvec[left+2].type == TYPE_FUNCTION) {

	                /* Separate case from above since you end up with
	                 * 1,-sin(1) --> 1 (1)
	                 * Here, just do
	                 * 1,-sin(1) --> 1,sin(1)
	                 * just remove unary operator
	                 */
	                //st_copy(&state.tokenvec[left+1], &state.tokenvec[left+2]);
	            	state.tokenvec[left+1] = state.tokenvec[left+2];
	                pos -= 1;
	                left = 0;
	                continue;
	            } else if ((state.tokenvec[left].type == TYPE_BAREWORD) &&
	                       (state.tokenvec[left+1].type == TYPE_DOT) &&
	                       (state.tokenvec[left+2].type == TYPE_BAREWORD)) {
	                /* ignore the '.n'
	                 * typically is this databasename.table
	                 */
	                assert(pos >= 3);
	                pos -= 2;
	                left = 0;
	                continue;
	            } else if ((state.tokenvec[left].type == TYPE_EXPRESSION) &&
	                       (state.tokenvec[left+1].type == TYPE_DOT) &&
	                       (state.tokenvec[left+2].type == TYPE_BAREWORD)) {
	                /* select . `foo` --> select `foo` */
	                //st_copy(&state.tokenvec[left+1], &state.tokenvec[left+2]);
	            	state.tokenvec[left+1] = state.tokenvec[left+2];
	                pos -= 1;
	                left = 0;
	                continue;
	            } else if ((state.tokenvec[left].type == TYPE_FUNCTION) &&
	                       (state.tokenvec[left+1].type == TYPE_LEFTPARENS) &&
	                       (state.tokenvec[left+2].type != TYPE_RIGHTPARENS)) {
	                /*
	                 * whats going on here
	                 * Some SQL functions like USER() have 0 args
	                 * if we get User(foo), then User is not a function
	                 * This should be expanded since it eliminated a lot of false
	                 * positives. 
	                 */
	                if  (state.tokenvec[left].val.toUpperCase().equals("USER")) {
	                    state.tokenvec[left].type = TYPE_BAREWORD;
	                }
	            }
			
/* --------------------------------------------------------------------------------------------------------------------------------------------------------*/

			/*
			 * assume left-most token is good, now use the existing 2 tokens --
			 * do not get another
			 */
			left += 1;

		} /* while(1) */

		/*
		 * if we have 4 or less tokens, and we had a comment token at the end,
		 * add it back
		 */
		if (left < LIBINJECTION_SQLI_MAX_TOKENS && last_comment.type == TYPE_COMMENT) {
			state.tokenvec[left] = last_comment;
			left += 1;
		}

		/*
		 * sometimes we grab a 6th token to help determine the type of token 5.
		 * --> what does this mean?
		 */
		if (left > LIBINJECTION_SQLI_MAX_TOKENS) {
			left = LIBINJECTION_SQLI_MAX_TOKENS;
		}

		return left;
	}

	/** See if two tokens can be merged since they are compound SQL phrases.
	 *
	 * This takes two tokens, and, if they are the right type,
	 * merges their values together.  Then checks to see if the
	 * new value is special using the PHRASES mapping.
	 *
	 * Example: "UNION" + "ALL" ==> "UNION ALL"
	 *
	 * C Security Notes: this is safe to use C-strings (null-terminated)
	 *  since the types involved by definition do not have embedded nulls
	 *  (e.g. there is no keyword with embedded null)
	 *
	 * Porting Notes: since this is C, it's oddly complicated.
	 *  This is just:  multikeywords[token.value + ' ' + token2.value]
	 *
	 */
	// Tokenize, return whether there are more characters to tokenize

	boolean libinjection_sqli_tokenize(State state) {
		/* UNFINISHED */
		int pos = state.pos;
		int slen = state.slen;
		int current = state.current;
		String s = state.s;

		if (slen == 0) {
			return false;
		}

		// clear token in current position
		state.tokenvec[current] = null;

		while (pos < slen) {
			char ch = s.charAt(pos); // current character
			// parse and tokenize character
			switch (ch) {
			 case 0 : pos = parse_white(state); break; /* 0 */
			 case 1 : pos = parse_white(state); break; /* 1 */
			 case 2 : pos = parse_white(state); break; /* 2 */
			 case 3 : pos = parse_white(state); break; /* 3 */
			 case 4 : pos = parse_white(state); break; /* 4 */
			 case 5 : pos = parse_white(state); break; /* 5 */
			 case 6 : pos = parse_white(state); break; /* 6 */
			 case 7 : pos = parse_white(state); break; /* 7 */
			 case 8 : pos = parse_white(state); break; /* 8 */
			 case 9 : pos = parse_white(state); break; /* 9 */
			 case 10 : pos = parse_white(state); break; /* 10 */
			 case 11 : pos = parse_white(state); break; /* 11 */
			 case 12 : pos = parse_white(state); break; /* 12 */
			 case 13 : pos = parse_white(state); break; /* 13 */
			 case 14 : pos = parse_white(state); break; /* 14 */
			 case 15 : pos = parse_white(state); break; /* 15 */
			 case 16 : pos = parse_white(state); break; /* 16 */
			 case 17 : pos = parse_white(state); break; /* 17 */
			 case 18 : pos = parse_white(state); break; /* 18 */
			 case 19 : pos = parse_white(state); break; /* 19 */
			 case 20 : pos = parse_white(state); break; /* 20 */
			 case 21 : pos = parse_white(state); break; /* 21 */
			 case 22 : pos = parse_white(state); break; /* 22 */
			 case 23 : pos = parse_white(state); break; /* 23 */
			 case 24 : pos = parse_white(state); break; /* 24 */
			 case 25 : pos = parse_white(state); break; /* 25 */
			 case 26 : pos = parse_white(state); break; /* 26 */
			 case 27 : pos = parse_white(state); break; /* 27 */
			 case 28 : pos = parse_white(state); break; /* 28 */
			 case 29 : pos = parse_white(state); break; /* 29 */
			 case 30 : pos = parse_white(state); break; /* 30 */
			 case 31 : pos = parse_white(state); break; /* 31 */
			 case 32 : pos = parse_white(state); break; /* 32 */
			// case 33 : pos = parse_operator2(state); break; /* 33 */
			// case 34 : pos = parse_string(state); break; /* 34 */
			// case 35 : pos = parse_hash(state); break; /* 35 */
			// case 36 : pos = parse_money(state); break; /* 36 */
			// case 37 : pos = parse_operator1(state); break; /* 37 */
			// case 38 : pos = parse_operator2(state); break; /* 38 */
			// case 39 : pos = parse_string(state); break; /* 39 */
			case 40 : pos = parse_char(state); break; /* 40 */
			case 41 : pos = parse_char(state); break; /* 41 */
			// case 42 : pos = parse_operator2(state); break; /* 42 */
			// case 43 : pos = parse_operator1(state); break; /* 43 */
			case 44 : pos = parse_char(state); break; /* 44 */
			// case 45 : pos = parse_dash(state); break; /* 45 */
			// case 46 : pos = parse_number(state); break; /* 46 */
			// case 47 : pos = parse_slash(state); break; /* 47 */
			// case 48 : pos = parse_number(state); break; /* 48 */
			// case 49 : pos = parse_number(state); break; /* 49 */
			// case 50 : pos = parse_number(state); break; /* 50 */
			// case 51 : pos = parse_number(state); break; /* 51 */
			// case 52 : pos = parse_number(state); break; /* 52 */
			// case 53 : pos = parse_number(state); break; /* 53 */
			// case 54 : pos = parse_number(state); break; /* 54 */
			// case 55 : pos = parse_number(state); break; /* 55 */
			// case 56 : pos = parse_number(state); break; /* 56 */
			// case 57 : pos = parse_number(state); break; /* 57 */
			// case 58 : pos = parse_operator2(state); break; /* 58 */
			case 59 : pos = parse_char(state); break; /* 59 */
			// case 60 : pos = parse_operator2(state); break; /* 60 */
			// case 61 : pos = parse_operator2(state); break; /* 61 */
			// case 62 : pos = parse_operator2(state); break; /* 62 */
			// case 63 : pos = parse_other(state); break; /* 63 */
			// case 64 : pos = parse_var(state); break; /* 64 */
			// case 65 : pos = parse_word(state); break; /* 65 */
			// case 66 : pos = parse_bstring(state); break; /* 66 */
			// case 67 : pos = parse_word(state); break; /* 67 */
			// case 68 : pos = parse_word(state); break; /* 68 */
			// case 69 : pos = parse_estring(state); break; /* 69 */
			// case 70 : pos = parse_word(state); break; /* 70 */
			// case 71 : pos = parse_word(state); break; /* 71 */
			// case 72 : pos = parse_word(state); break; /* 72 */
			// case 73 : pos = parse_word(state); break; /* 73 */
			// case 74 : pos = parse_word(state); break; /* 74 */
			// case 75 : pos = parse_word(state); break; /* 75 */
			// case 76 : pos = parse_word(state); break; /* 76 */
			// case 77 : pos = parse_word(state); break; /* 77 */
			// case 78 : pos = parse_nqstring(state); break; /* 78 */
			// case 79 : pos = parse_word(state); break; /* 79 */
			// case 80 : pos = parse_word(state); break; /* 80 */
			// case 81 : pos = parse_qstring(state); break; /* 81 */
			// case 82 : pos = parse_word(state); break; /* 82 */
			// case 83 : pos = parse_word(state); break; /* 83 */
			// case 84 : pos = parse_word(state); break; /* 84 */
			// case 85 : pos = parse_ustring(state); break; /* 85 */
			// case 86 : pos = parse_word(state); break; /* 86 */
			// case 87 : pos = parse_word(state); break; /* 87 */
			// case 88 : pos = parse_xstring(state); break; /* 88 */
			// case 89 : pos = parse_word(state); break; /* 89 */
			// case 90 : pos = parse_word(state); break; /* 90 */
			// case 91 : pos = parse_bword(state); break; /* 91 */
			// case 92 : pos = parse_backslash(state); break; /* 92 */
			// case 93 : pos = parse_other(state); break; /* 93 */
			// case 94 : pos = parse_operator1(state); break; /* 94 */
			// case 95 : pos = parse_word(state); break; /* 95 */
			// case 96 : pos = parse_tick(state); break; /* 96 */
			// case 97 : pos = parse_word(state); break; /* 97 */
			// case 98 : pos = parse_bstring(state); break; /* 98 */
			// case 99 : pos = parse_word(state); break; /* 99 */
			// case 100: pos = parse_word(state); break; /* 100 */
			// case 101: pos = parse_estring(state); break; /* 101 */
			// case 102: pos = parse_word(state); break; /* 102 */
			// case 103: pos = parse_word(state); break; /* 103 */
			// case 104: pos = parse_word(state); break; /* 104 */
			// case 105: pos = parse_word(state); break; /* 105 */
			// case 106: pos = parse_word(state); break; /* 106 */
			// case 107: pos = parse_word(state); break; /* 107 */
			// case 108: pos = parse_word(state); break; /* 108 */
			// case 109: pos = parse_word(state); break; /* 109 */
			// case 110: pos = parse_nqstring(state); break; /* 110 */
			// case 111: pos = parse_word(state); break; /* 111 */
			// case 112: pos = parse_word(state); break; /* 112 */
			// case 113: pos = parse_qstring(state); break; /* 113 */
			// case 114: pos = parse_word(state); break; /* 114 */
			// case 115: pos = parse_word(state); break; /* 115 */
			// case 116: pos = parse_word(state); break; /* 116 */
			// case 117: pos = parse_ustring(state); break; /* 117 */
			// case 118: pos = parse_word(state); break; /* 118 */
			// case 119: pos = parse_word(state); break; /* 119 */
			// case 120: pos = parse_xstring(state); break; /* 120 */
			// case 121: pos = parse_word(state); break; /* 121 */
			// case 122: pos = parse_word(state); break; /* 122 */
			case 123 : pos = parse_char(state); break; /* 123 */
			// case 124: pos = parse_operator2(state); break; /* 124 */
			case 125: pos = parse_char(state); break; /* 125 */
			// case 126: pos = parse_operator1(state); break; /* 126 */
			case 127: pos = parse_white(state); break; /* 127 */
			// case 128: pos = parse_word(state); break; /* 128 */
			// case 129: pos = parse_word(state); break; /* 129 */
			// case 130: pos = parse_word(state); break; /* 130 */
			// case 131: pos = parse_word(state); break; /* 131 */
			// case 132: pos = parse_word(state); break; /* 132 */
			// case 133: pos = parse_word(state); break; /* 133 */
			// case 134: pos = parse_word(state); break; /* 134 */
			// case 135: pos = parse_word(state); break; /* 135 */
			// case 136: pos = parse_word(state); break; /* 136 */
			// case 137: pos = parse_word(state); break; /* 137 */
			// case 138: pos = parse_word(state); break; /* 138 */
			// case 139: pos = parse_word(state); break; /* 139 */
			// case 140: pos = parse_word(state); break; /* 140 */
			// case 141: pos = parse_word(state); break; /* 141 */
			// case 142: pos = parse_word(state); break; /* 142 */
			// case 143: pos = parse_word(state); break; /* 143 */
			// case 144: pos = parse_word(state); break; /* 144 */
			// case 145: pos = parse_word(state); break; /* 145 */
			// case 146: pos = parse_word(state); break; /* 146 */
			// case 147: pos = parse_word(state); break; /* 147 */
			// case 148: pos = parse_word(state); break; /* 148 */
			// case 149: pos = parse_word(state); break; /* 149 */
			// case 150: pos = parse_word(state); break; /* 150 */
			// case 151: pos = parse_word(state); break; /* 151 */
			// case 152: pos = parse_word(state); break; /* 152 */
			// case 153: pos = parse_word(state); break; /* 153 */
			// case 154: pos = parse_word(state); break; /* 154 */
			// case 155: pos = parse_word(state); break; /* 155 */
			// case 156: pos = parse_word(state); break; /* 156 */
			// case 157: pos = parse_word(state); break; /* 157 */
			// case 158: pos = parse_word(state); break; /* 158 */
			// case 159: pos = parse_word(state); break; /* 159 */
			case 160: pos = parse_white(state); break; /* 160 */
			// case 161: pos = parse_word(state); break; /* 161 */
			// case 162: pos = parse_word(state); break; /* 162 */
			// case 163: pos = parse_word(state); break; /* 163 */
			// case 164: pos = parse_word(state); break; /* 164 */
			// case 165: pos = parse_word(state); break; /* 165 */
			// case 166: pos = parse_word(state); break; /* 166 */
			// case 167: pos = parse_word(state); break; /* 167 */
			// case 168: pos = parse_word(state); break; /* 168 */
			// case 169: pos = parse_word(state); break; /* 169 */
			// case 170: pos = parse_word(state); break; /* 170 */
			// case 171: pos = parse_word(state); break; /* 171 */
			// case 172: pos = parse_word(state); break; /* 172 */
			// case 173: pos = parse_word(state); break; /* 173 */
			// case 174: pos = parse_word(state); break; /* 174 */
			// case 175: pos = parse_word(state); break; /* 175 */
			// case 176: pos = parse_word(state); break; /* 176 */
			// case 177: pos = parse_word(state); break; /* 177 */
			// case 178: pos = parse_word(state); break; /* 178 */
			// case 179: pos = parse_word(state); break; /* 179 */
			// case 180: pos = parse_word(state); break; /* 180 */
			// case 181: pos = parse_word(state); break; /* 181 */
			// case 182: pos = parse_word(state); break; /* 182 */
			// case 183: pos = parse_word(state); break; /* 183 */
			// case 184: pos = parse_word(state); break; /* 184 */
			// case 185: pos = parse_word(state); break; /* 185 */
			// case 186: pos = parse_word(state); break; /* 186 */
			// case 187: pos = parse_word(state); break; /* 187 */
			// case 188: pos = parse_word(state); break; /* 188 */
			// case 189: pos = parse_word(state); break; /* 189 */
			// case 190: pos = parse_word(state); break; /* 190 */
			// case 191: pos = parse_word(state); break; /* 191 */
			// case 192: pos = parse_word(state); break; /* 192 */
			// case 193: pos = parse_word(state); break; /* 193 */
			// case 194: pos = parse_word(state); break; /* 194 */
			// case 195: pos = parse_word(state); break; /* 195 */
			// case 196: pos = parse_word(state); break; /* 196 */
			// case 197: pos = parse_word(state); break; /* 197 */
			// case 198: pos = parse_word(state); break; /* 198 */
			// case 199: pos = parse_word(state); break; /* 199 */
			// case 200: pos = parse_word(state); break; /* 200 */
			// case 201: pos = parse_word(state); break; /* 201 */
			// case 202: pos = parse_word(state); break; /* 202 */
			// case 203: pos = parse_word(state); break; /* 203 */
			// case 204: pos = parse_word(state); break; /* 204 */
			// case 205: pos = parse_word(state); break; /* 205 */
			// case 206: pos = parse_word(state); break; /* 206 */
			// case 207: pos = parse_word(state); break; /* 207 */
			// case 208: pos = parse_word(state); break; /* 208 */
			// case 209: pos = parse_word(state); break; /* 209 */
			// case 210: pos = parse_word(state); break; /* 210 */
			// case 211: pos = parse_word(state); break; /* 211 */
			// case 212: pos = parse_word(state); break; /* 212 */
			// case 213: pos = parse_word(state); break; /* 213 */
			// case 214: pos = parse_word(state); break; /* 214 */
			// case 215: pos = parse_word(state); break; /* 215 */
			// case 216: pos = parse_word(state); break; /* 216 */
			// case 217: pos = parse_word(state); break; /* 217 */
			// case 218: pos = parse_word(state); break; /* 218 */
			// case 219: pos = parse_word(state); break; /* 219 */
			// case 220: pos = parse_word(state); break; /* 220 */
			// case 221: pos = parse_word(state); break; /* 221 */
			// case 222: pos = parse_word(state); break; /* 222 */
			// case 223: pos = parse_word(state); break; /* 223 */
			// case 224: pos = parse_word(state); break; /* 224 */
			// case 225: pos = parse_word(state); break; /* 225 */
			// case 226: pos = parse_word(state); break; /* 226 */
			// case 227: pos = parse_word(state); break; /* 227 */
			// case 228: pos = parse_word(state); break; /* 228 */
			// case 229: pos = parse_word(state); break; /* 229 */
			// case 230: pos = parse_word(state); break; /* 230 */
			// case 231: pos = parse_word(state); break; /* 231 */
			// case 232: pos = parse_word(state); break; /* 232 */
			// case 233: pos = parse_word(state); break; /* 233 */
			// case 234: pos = parse_word(state); break; /* 234 */
			// case 235: pos = parse_word(state); break; /* 235 */
			// case 236: pos = parse_word(state); break; /* 236 */
			// case 237: pos = parse_word(state); break; /* 237 */
			// case 238: pos = parse_word(state); break; /* 238 */
			// case 239: pos = parse_word(state); break; /* 239 */
			// case 240: pos = parse_word(state); break; /* 240 */
			// case 241: pos = parse_word(state); break; /* 241 */
			// case 242: pos = parse_word(state); break; /* 242 */
			// case 243: pos = parse_word(state); break; /* 243 */
			// case 244: pos = parse_word(state); break; /* 244 */
			// case 245: pos = parse_word(state); break; /* 245 */
			// case 246: pos = parse_word(state); break; /* 246 */
			// case 247: pos = parse_word(state); break; /* 247 */
			// case 248: pos = parse_word(state); break; /* 248 */
			// case 249: pos = parse_word(state); break; /* 249 */
			// case 250: pos = parse_word(state); break; /* 250 */
			// case 251: pos = parse_word(state); break; /* 251 */
			// case 252: pos = parse_word(state); break; /* 252 */
			// case 253: pos = parse_word(state); break; /* 253 */
			// case 254: pos = parse_word(state); break; /* 254 */
			// case 255: pos = parse_word(state); break; /* 255 */
			}
			state.pos = pos;

			if (state.tokenvec[current] != null) {
				state.stats_tokens += 1;
				return true;
			}
		}
		return false;
	}

	/* Parsers */
	
	boolean syntax_merge_words(State state, Token a, int apos, Token b, int bpos) {
		String merged;
		Character wordtype;
		
        // first token must not represent any of these types
	    if (!
	        (a.type == TYPE_KEYWORD ||
	         a.type == TYPE_BAREWORD ||
	         a.type == TYPE_OPERATOR ||
	         a.type == TYPE_UNION ||
	         a.type == TYPE_FUNCTION ||
	         a.type == TYPE_EXPRESSION ||
	         a.type == TYPE_SQLTYPE)) {
	        return false;
	    }

	    // second token must not represent any of these types
	    if (b.type != TYPE_KEYWORD  && b.type != TYPE_BAREWORD &&
	        b.type != TYPE_OPERATOR && b.type != TYPE_SQLTYPE &&
	        b.type != TYPE_LOGIC_OPERATOR &&
	        b.type != TYPE_FUNCTION &&
	        b.type != TYPE_UNION    && b.type != TYPE_EXPRESSION) {
	        return false;
	    }
	    
	    merged = a.val + " " + b.val;
	    wordtype = libinjection_sqli_lookup_word(merged);
	    
	    if (wordtype != null) {
	    	Token token = new Token(wordtype, a.pos, a.len, merged);
	    	state.tokenvec[apos] = token;
	    	// shift down all tokens after b by one index --> dunno if needed since there may not be any tokens after b. take closer look at fold
	    	for (int i = bpos; i < state.tokenvec.length-1; i++) {
	    		if (state.tokenvec[i] != null) {
	    			state.tokenvec[i] = state.tokenvec[i+1];
	    		} else {
	    			break;
	    		}
	    	}
	    	return true;
	    }
	    else {
	    	return false;
	    }
	    
	    
	}
	
	
	int parse_white(State state) {
		return state.pos + 1;
	}

	int parse_char(State state) {
		String s = state.s;
		int pos = state.pos;
		Token token = new Token(s.charAt(pos), pos, 1, String.valueOf(s.charAt(pos)));
		state.tokenvec[state.current] = token;
		return pos + 1;
	}

	/* Token methods */
	boolean token_is_unary_op(Token token) {
		String str = token.val;
		int len = token.len;

		if (token.type != TYPE_OPERATOR) {
			return false;
		}

		switch (len) {
		case 1:
			return str.charAt(0) == '+' || str.charAt(0) == '-' || str.charAt(0) == '!' || str.charAt(0) == '~';
		case 2:
			return str.charAt(0) == '!' && str.charAt(1) == '!';
		case 3:
			return str.toUpperCase().equals("NOT");
		default:
			return false;
		}
	}

	
	boolean token_is_arithmetic_op(Token token) {
		char ch = token.val.charAt(0);
		return (token.type == TYPE_OPERATOR && token.len == 1 &&
				(ch == '*' || ch == '/' || ch == '-' || ch == '+' || ch == '%'));
	}
}

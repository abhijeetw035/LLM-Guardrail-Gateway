// Package dsl implements the lexer for the policy language.
//
// The lexer converts raw .policy text into a flat slice of tokens.
// Each token has a type and a literal string value.
//
// Grammar overview:
//
//	policy tenant:<name> {
//	  rule <name> {
//	    when <condition>
//	    action BLOCK | TAG | LOG
//	    reason "<string>"
//	  }
//	}
//
// Condition grammar:
//
//	condition  = atom { ("AND" | "OR") atom }
//	atom       = field ">" number
//	           | field "<" number
//	           | field "==" string
//	           | field "NOT_IN" "[" string { "," string } "]"
package dsl

import (
	"fmt"
	"strings"
	"unicode"
)

// TokenType identifies the kind of a lexed token.
type TokenType int

const (
	// Keywords
	TPOLICY  TokenType = iota // policy
	TRULE                     // rule
	TWHEN                     // when
	TACTION                   // action
	TREASON                   // reason
	TAND                      // AND
	TOR                       // OR
	TNOT_IN                   // NOT_IN

	// Literals / identifiers
	TIDENT  // identifier or dotted field path (e.g. input.risk_score)
	TSTRING // "quoted string"
	TNUMBER // numeric literal (e.g. 0.8)

	// Operators
	TGT // >
	TLT // <
	TEQ // ==

	// Punctuation
	TLBRACE   // {
	TRBRACE   // }
	TLBRACKET // [
	TRBRACKET // ]
	TCOMMA    // ,
	TCOLON    // :

	TEOF
)

func (t TokenType) String() string {
	names := [...]string{
		"POLICY", "RULE", "WHEN", "ACTION", "REASON",
		"AND", "OR", "NOT_IN",
		"IDENT", "STRING", "NUMBER",
		">", "<", "==",
		"{", "}", "[", "]", ",", ":",
		"EOF",
	}
	if int(t) < len(names) {
		return names[t]
	}
	return fmt.Sprintf("Token(%d)", t)
}

// Token is a single lexed unit.
type Token struct {
	Type    TokenType
	Literal string
	Line    int
}

var keywords = map[string]TokenType{
	"policy":  TPOLICY,
	"rule":    TRULE,
	"when":    TWHEN,
	"action":  TACTION,
	"reason":  TREASON,
	"AND":     TAND,
	"OR":      TOR,
	"NOT_IN":  TNOT_IN,
	"BLOCK":   TIDENT, // kept as IDENT so parser handles action values
	"TAG":     TIDENT,
	"LOG":     TIDENT,
	"REDACT":  TIDENT,
}

// Lex tokenises src and returns the token slice.
// Returns an error if an unexpected character is encountered.
func Lex(src string) ([]Token, error) {
	l := &lexer{src: src, line: 1}
	return l.run()
}

type lexer struct {
	src  string
	pos  int
	line int
}

func (l *lexer) run() ([]Token, error) {
	var tokens []Token
	for {
		l.skipWhitespaceAndComments()
		if l.pos >= len(l.src) {
			tokens = append(tokens, Token{Type: TEOF, Line: l.line})
			break
		}

		ch := l.src[l.pos]

		switch {
		case ch == '"':
			s, err := l.readString()
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, Token{Type: TSTRING, Literal: s, Line: l.line})

		case ch == '>':
			tokens = append(tokens, Token{Type: TGT, Literal: ">", Line: l.line})
			l.pos++

		case ch == '<':
			tokens = append(tokens, Token{Type: TLT, Literal: "<", Line: l.line})
			l.pos++

		case ch == '=' && l.peek(1) == '=':
			tokens = append(tokens, Token{Type: TEQ, Literal: "==", Line: l.line})
			l.pos += 2

		case ch == '{':
			tokens = append(tokens, Token{Type: TLBRACE, Literal: "{", Line: l.line})
			l.pos++

		case ch == '}':
			tokens = append(tokens, Token{Type: TRBRACE, Literal: "}", Line: l.line})
			l.pos++

		case ch == '[':
			tokens = append(tokens, Token{Type: TLBRACKET, Literal: "[", Line: l.line})
			l.pos++

		case ch == ']':
			tokens = append(tokens, Token{Type: TRBRACKET, Literal: "]", Line: l.line})
			l.pos++

		case ch == ',':
			tokens = append(tokens, Token{Type: TCOMMA, Literal: ",", Line: l.line})
			l.pos++

		case ch == ':':
			tokens = append(tokens, Token{Type: TCOLON, Literal: ":", Line: l.line})
			l.pos++

		case isDigit(ch) || (ch == '-' && l.pos+1 < len(l.src) && isDigit(l.src[l.pos+1])):
			num := l.readNumber()
			tokens = append(tokens, Token{Type: TNUMBER, Literal: num, Line: l.line})

		case isIdentStart(ch):
			word := l.readIdent()
			tt, ok := keywords[word]
			if !ok {
				tt = TIDENT
			}
			tokens = append(tokens, Token{Type: tt, Literal: word, Line: l.line})

		default:
			return nil, fmt.Errorf("line %d: unexpected character %q", l.line, ch)
		}
	}
	return tokens, nil
}

func (l *lexer) skipWhitespaceAndComments() {
	for l.pos < len(l.src) {
		ch := l.src[l.pos]
		if ch == '\n' {
			l.line++
			l.pos++
		} else if unicode.IsSpace(rune(ch)) {
			l.pos++
		} else if ch == '#' {
			// Line comment — skip to end of line
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
		} else {
			break
		}
	}
}

func (l *lexer) peek(offset int) byte {
	if l.pos+offset < len(l.src) {
		return l.src[l.pos+offset]
	}
	return 0
}

func (l *lexer) readString() (string, error) {
	l.pos++ // consume opening "
	var sb strings.Builder
	for l.pos < len(l.src) {
		ch := l.src[l.pos]
		if ch == '"' {
			l.pos++
			return sb.String(), nil
		}
		if ch == '\n' {
			return "", fmt.Errorf("line %d: unterminated string", l.line)
		}
		sb.WriteByte(ch)
		l.pos++
	}
	return "", fmt.Errorf("line %d: unterminated string at EOF", l.line)
}

func (l *lexer) readNumber() string {
	start := l.pos
	if l.src[l.pos] == '-' {
		l.pos++
	}
	for l.pos < len(l.src) && (isDigit(l.src[l.pos]) || l.src[l.pos] == '.') {
		l.pos++
	}
	return l.src[start:l.pos]
}

func (l *lexer) readIdent() string {
	start := l.pos
	for l.pos < len(l.src) && isIdentContinue(l.src[l.pos]) {
		l.pos++
	}
	return l.src[start:l.pos]
}

func isIdentStart(ch byte) bool {
	return ch == '_' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}

func isIdentContinue(ch byte) bool {
	return isIdentStart(ch) || isDigit(ch) || ch == '.' || ch == '-'
}

func isDigit(ch byte) bool { return ch >= '0' && ch <= '9' }

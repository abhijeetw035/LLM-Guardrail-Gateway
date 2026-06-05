// Package dsl — parser.
//
// A recursive descent parser that consumes the token stream produced by the
// lexer and returns an AST rooted at PolicyNode.
//
// Grammar (simplified BNF):
//
//	policy    = "policy" "tenant" ":" IDENT "{" rule* "}"
//	rule      = "rule" IDENT "{" "when" condition "action" action_val "reason" STRING "}"
//	condition = atom { ("AND" | "OR") atom }
//	atom      = field ">" NUMBER
//	          | field "<" NUMBER
//	          | field "==" STRING
//	          | field "NOT_IN" "[" STRING { "," STRING } "]"
//	field     = IDENT
//	action_val= "BLOCK" | "TAG" | "LOG" | "REDACT"
package dsl

import (
	"fmt"
	"strconv"
)

// --- AST node types ---

// Node is the interface all AST nodes satisfy.
type Node interface{ nodeTag() }

// PolicyNode is the root of a parsed policy file.
type PolicyNode struct {
	TenantID string
	Rules    []*RuleNode
}

func (*PolicyNode) nodeTag() {}

// RuleNode represents one named rule.
type RuleNode struct {
	Name      string
	Condition Node // subtree of condition nodes
	Action    string
	Reason    string
}

func (*RuleNode) nodeTag() {}

// BinaryExprNode is AND / OR of two condition subtrees.
type BinaryExprNode struct {
	Op    string // "AND" | "OR"
	Left  Node
	Right Node
}

func (*BinaryExprNode) nodeTag() {}

// CompareNode is field OP value (>, <, ==).
type CompareNode struct {
	Field string
	Op    string  // ">" | "<" | "=="
	Value string  // raw string; parser stores as-is, compiler converts to correct type
}

func (*CompareNode) nodeTag() {}

// NotInNode is field NOT_IN [list].
type NotInNode struct {
	Field  string
	Values []string
}

func (*NotInNode) nodeTag() {}

// --- Parser ---

type parser struct {
	tokens []Token
	pos    int
}

// Parse runs the lexer and parser over src, returning the root PolicyNode.
func Parse(src string) (*PolicyNode, error) {
	tokens, err := Lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{tokens: tokens}
	return p.parsePolicy()
}

func (p *parser) cur() Token {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return Token{Type: TEOF}
}

func (p *parser) peek() Token {
	if p.pos+1 < len(p.tokens) {
		return p.tokens[p.pos+1]
	}
	return Token{Type: TEOF}
}

func (p *parser) consume() Token {
	t := p.cur()
	p.pos++
	return t
}

func (p *parser) expect(tt TokenType) (Token, error) {
	t := p.cur()
	if t.Type != tt {
		return t, fmt.Errorf("line %d: expected %s, got %s (%q)", t.Line, tt, t.Type, t.Literal)
	}
	p.pos++
	return t, nil
}

// parsePolicy parses: policy tenant:<ident> { rule* }
func (p *parser) parsePolicy() (*PolicyNode, error) {
	if _, err := p.expect(TPOLICY); err != nil {
		return nil, err
	}
	// "tenant" is parsed as TIDENT because it's not a keyword
	tenantKw := p.cur()
	if tenantKw.Type != TIDENT || tenantKw.Literal != "tenant" {
		return nil, fmt.Errorf("line %d: expected 'tenant', got %q", tenantKw.Line, tenantKw.Literal)
	}
	p.consume()

	if _, err := p.expect(TCOLON); err != nil {
		return nil, err
	}

	tenantID, err := p.expect(TIDENT)
	if err != nil {
		return nil, err
	}

	if _, err := p.expect(TLBRACE); err != nil {
		return nil, err
	}

	node := &PolicyNode{TenantID: tenantID.Literal}
	for p.cur().Type == TRULE {
		rule, err := p.parseRule()
		if err != nil {
			return nil, err
		}
		node.Rules = append(node.Rules, rule)
	}

	if _, err := p.expect(TRBRACE); err != nil {
		return nil, err
	}
	return node, nil
}

// parseRule parses: rule <name> { when <cond> action <val> reason "<str>" }
func (p *parser) parseRule() (*RuleNode, error) {
	if _, err := p.expect(TRULE); err != nil {
		return nil, err
	}
	name, err := p.expect(TIDENT)
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(TLBRACE); err != nil {
		return nil, err
	}
	if _, err := p.expect(TWHEN); err != nil {
		return nil, err
	}

	cond, err := p.parseCondition()
	if err != nil {
		return nil, err
	}

	if _, err := p.expect(TACTION); err != nil {
		return nil, err
	}
	actionTok := p.consume() // BLOCK, TAG, LOG, REDACT — all lexed as TIDENT
	if actionTok.Type != TIDENT {
		return nil, fmt.Errorf("line %d: expected action value, got %s", actionTok.Line, actionTok.Type)
	}

	if _, err := p.expect(TREASON); err != nil {
		return nil, err
	}
	reasonTok, err := p.expect(TSTRING)
	if err != nil {
		return nil, err
	}

	if _, err := p.expect(TRBRACE); err != nil {
		return nil, err
	}

	return &RuleNode{
		Name:      name.Literal,
		Condition: cond,
		Action:    actionTok.Literal,
		Reason:    reasonTok.Literal,
	}, nil
}

// parseCondition parses atom { AND|OR atom } with left-to-right association.
func (p *parser) parseCondition() (Node, error) {
	left, err := p.parseAtom()
	if err != nil {
		return nil, err
	}
	for p.cur().Type == TAND || p.cur().Type == TOR {
		op := p.consume().Literal
		right, err := p.parseAtom()
		if err != nil {
			return nil, err
		}
		left = &BinaryExprNode{Op: op, Left: left, Right: right}
	}
	return left, nil
}

// parseAtom parses one condition leaf: compare or NOT_IN.
func (p *parser) parseAtom() (Node, error) {
	field, err := p.expect(TIDENT)
	if err != nil {
		return nil, err
	}

	switch p.cur().Type {
	case TGT, TLT, TEQ:
		op := p.consume()
		val, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		return &CompareNode{Field: field.Literal, Op: op.Literal, Value: val}, nil

	case TNOT_IN:
		p.consume()
		if _, err := p.expect(TLBRACKET); err != nil {
			return nil, err
		}
		var vals []string
		for p.cur().Type != TRBRACKET && p.cur().Type != TEOF {
			v, err := p.expect(TSTRING)
			if err != nil {
				return nil, err
			}
			vals = append(vals, v.Literal)
			if p.cur().Type == TCOMMA {
				p.consume()
			}
		}
		if _, err := p.expect(TRBRACKET); err != nil {
			return nil, err
		}
		return &NotInNode{Field: field.Literal, Values: vals}, nil

	default:
		t := p.cur()
		return nil, fmt.Errorf("line %d: expected operator after field %q, got %s", t.Line, field.Literal, t.Type)
	}
}

// parseValue reads a STRING or NUMBER token and returns its raw string.
func (p *parser) parseValue() (string, error) {
	t := p.cur()
	switch t.Type {
	case TSTRING:
		p.consume()
		return t.Literal, nil
	case TNUMBER:
		p.consume()
		// Validate it's actually a number
		if _, err := strconv.ParseFloat(t.Literal, 64); err != nil {
			return "", fmt.Errorf("line %d: invalid number %q", t.Line, t.Literal)
		}
		return t.Literal, nil
	default:
		return "", fmt.Errorf("line %d: expected string or number, got %s %q", t.Line, t.Type, t.Literal)
	}
}

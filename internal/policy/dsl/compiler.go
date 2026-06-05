// Package dsl — compiler and evaluator.
//
// The compiler walks the AST produced by the parser and builds a slice of
// CompiledRule. Each CompiledRule has a pre-built condition closure that
// takes an EvalContext and returns bool. At request time only the closure
// is called — no AST traversal happens on the hot path.
//
// EvalContext is the set of values available during evaluation. It is built
// once per request and passed to every rule.
package dsl

import (
	"fmt"
	"strconv"
	"strings"
)

// Action is the verdict a compiled rule can produce.
type Action string

const (
	ActionBlock  Action = "BLOCK"
	ActionTag    Action = "TAG"
	ActionLog    Action = "LOG"
	ActionRedact Action = "REDACT"
)

// EvalContext holds the request-time values that rule conditions can reference.
// All numeric scores are float64; string fields are compared case-insensitively.
type EvalContext struct {
	// Input fields
	InputRiskScore float64 // composite score from the input scanner (0.0–1.0)

	// Request fields
	RequestModel string // model name requested by client

	// Tenant fields
	TenantDailyTokens float64 // tokens consumed today by this tenant
}

// CompiledRule is a rule with its condition pre-compiled into a closure.
// At request time, call Condition(ctx) — no parsing or AST traversal needed.
type CompiledRule struct {
	Name      string
	Condition func(EvalContext) bool
	Action    Action
	Reason    string
}

// Verdict is returned by Evaluate for the first matching rule.
type Verdict struct {
	Matched  bool
	RuleName string
	Action   Action
	Reason   string
}

// Evaluate runs all compiled rules against ctx and returns the first match.
// Rules are evaluated in declaration order; the first match wins.
func Evaluate(rules []CompiledRule, ctx EvalContext) Verdict {
	for _, r := range rules {
		if r.Condition(ctx) {
			return Verdict{Matched: true, RuleName: r.Name, Action: r.Action, Reason: r.Reason}
		}
	}
	return Verdict{}
}

// Compile walks a PolicyNode AST and returns the compiled rule slice.
// Returns an error if a condition references an unknown field or uses an
// incompatible operator/type combination.
func Compile(policy *PolicyNode) ([]CompiledRule, error) {
	rules := make([]CompiledRule, 0, len(policy.Rules))
	for _, rn := range policy.Rules {
		cond, err := compileNode(rn.Condition)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", rn.Name, err)
		}
		action, err := parseAction(rn.Action)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", rn.Name, err)
		}
		rules = append(rules, CompiledRule{
			Name:      rn.Name,
			Condition: cond,
			Action:    action,
			Reason:    rn.Reason,
		})
	}
	return rules, nil
}

// compileNode recursively turns an AST node into a condition closure.
func compileNode(n Node) (func(EvalContext) bool, error) {
	switch node := n.(type) {

	case *BinaryExprNode:
		left, err := compileNode(node.Left)
		if err != nil {
			return nil, err
		}
		right, err := compileNode(node.Right)
		if err != nil {
			return nil, err
		}
		switch node.Op {
		case "AND":
			return func(ctx EvalContext) bool { return left(ctx) && right(ctx) }, nil
		case "OR":
			return func(ctx EvalContext) bool { return left(ctx) || right(ctx) }, nil
		default:
			return nil, fmt.Errorf("unknown binary op %q", node.Op)
		}

	case *CompareNode:
		return compileCompare(node)

	case *NotInNode:
		return compileNotIn(node)

	default:
		return nil, fmt.Errorf("unknown node type %T", n)
	}
}

// compileCompare builds a closure for field OP value.
func compileCompare(n *CompareNode) (func(EvalContext) bool, error) {
	getter, kind, err := fieldGetter(n.Field)
	if err != nil {
		return nil, err
	}

	switch kind {
	case "float":
		numVal, err := strconv.ParseFloat(n.Value, 64)
		if err != nil {
			return nil, fmt.Errorf("field %q expects a number, got %q", n.Field, n.Value)
		}
		switch n.Op {
		case ">":
			return func(ctx EvalContext) bool { return getter(ctx) > numVal }, nil
		case "<":
			return func(ctx EvalContext) bool { return getter(ctx) < numVal }, nil
		case "==":
			return func(ctx EvalContext) bool { return getter(ctx) == numVal }, nil
		}

	case "string":
		strVal := strings.ToLower(n.Value)
		strGetter, err := stringFieldGetter(n.Field)
		if err != nil {
			return nil, err
		}
		if n.Op != "==" {
			return nil, fmt.Errorf("field %q is a string; only == is supported, got %q", n.Field, n.Op)
		}
		return func(ctx EvalContext) bool {
			return strings.ToLower(strGetter(ctx)) == strVal
		}, nil
	}

	return nil, fmt.Errorf("unsupported op %q for field %q", n.Op, n.Field)
}

// compileNotIn builds a closure for field NOT_IN [list].
func compileNotIn(n *NotInNode) (func(EvalContext) bool, error) {
	strGetter, err := stringFieldGetter(n.Field)
	if err != nil {
		return nil, err
	}
	// Build a lowercase set for O(1) lookup at eval time.
	allowed := make(map[string]struct{}, len(n.Values))
	for _, v := range n.Values {
		allowed[strings.ToLower(v)] = struct{}{}
	}
	return func(ctx EvalContext) bool {
		val := strings.ToLower(strGetter(ctx))
		_, ok := allowed[val]
		return !ok // NOT_IN: true when value is NOT in the set
	}, nil
}

// fieldGetter returns a float64 accessor and kind="float" for numeric fields,
// or kind="string" (and a nil getter) for string fields, so callers know which
// path to take.
func fieldGetter(field string) (func(EvalContext) float64, string, error) {
	switch field {
	case "input.risk_score":
		return func(ctx EvalContext) float64 { return ctx.InputRiskScore }, "float", nil
	case "tenant.daily_tokens":
		return func(ctx EvalContext) float64 { return ctx.TenantDailyTokens }, "float", nil
	case "request.model":
		return nil, "string", nil
	default:
		return nil, "", fmt.Errorf("unknown field %q", field)
	}
}

// stringFieldGetter returns an accessor for string-typed fields.
func stringFieldGetter(field string) (func(EvalContext) string, error) {
	switch field {
	case "request.model":
		return func(ctx EvalContext) string { return ctx.RequestModel }, nil
	default:
		return nil, fmt.Errorf("field %q is not a string field", field)
	}
}

func parseAction(s string) (Action, error) {
	switch Action(strings.ToUpper(s)) {
	case ActionBlock:
		return ActionBlock, nil
	case ActionTag:
		return ActionTag, nil
	case ActionLog:
		return ActionLog, nil
	case ActionRedact:
		return ActionRedact, nil
	default:
		return "", fmt.Errorf("unknown action %q (valid: BLOCK, TAG, LOG, REDACT)", s)
	}
}

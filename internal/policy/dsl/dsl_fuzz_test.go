package dsl

import (
	"testing"
)

// FuzzLexer sends arbitrary strings through the lexer.
// Goal: ensure the lexer never panics on any input.
func FuzzLexer(f *testing.F) {
	// Seed corpus with valid policy fragments and edge cases.
	seeds := []string{
		`policy tenant:dev { rule r1 { when input.risk_score > 0.5 action BLOCK reason "blocked" } }`,
		``,
		`policy`,
		`{{{`,
		`"unterminated string`,
		`rule rule rule rule`,
		`> < == NOT_IN`,
		`policy tenant:dev { }`,
		`123.456.789`,
		`"hello" "world" "nested \"escape\""`,
		"policy tenant:x {\n  rule r {\n    when input.risk_score > 0.0 AND request.model == \"test\"\n    action TAG\n    reason \"test\"\n  }\n}",
		`policy tenant:dev { rule restrict { when request.model NOT_IN ["a", "b", "c"] action BLOCK reason "no" } }`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic. Errors are expected and fine.
		_, _ = Lex(input)
	})
}

// FuzzParser sends arbitrary strings through the full lex → parse pipeline.
// Goal: ensure the parser never panics on any token stream.
func FuzzParser(f *testing.F) {
	seeds := []string{
		`policy tenant:dev { rule r1 { when input.risk_score > 0.5 action BLOCK reason "blocked" } }`,
		`policy tenant:test { }`,
		``,
		`policy tenant:dev { rule r1 { when input.risk_score > 0.5 AND request.model == "x" action TAG reason "test" } }`,
		`garbage input that is not valid policy DSL at all`,
		`policy tenant:dev { rule r1 { when request.model NOT_IN ["a","b"] action BLOCK reason "nope" } }`,
		`policy tenant:dev { rule r1 { when input.risk_score > 0.5 action INVALID_ACTION reason "test" } }`,
		`policy { }`,
		`rule r1 { when x > 1 action BLOCK reason "no policy wrapper" }`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic. Parse errors are expected and fine.
		_, _ = Parse(input)
	})
}

// FuzzCompile sends arbitrary strings through lex → parse → compile.
// Goal: ensure the compiler never panics on any AST.
func FuzzCompile(f *testing.F) {
	seeds := []string{
		`policy tenant:dev { rule r1 { when input.risk_score > 0.5 action BLOCK reason "blocked" } }`,
		`policy tenant:dev { rule r1 { when tenant.daily_tokens > 100 action BLOCK reason "quota" } rule r2 { when request.model NOT_IN ["a"] action TAG reason "model" } }`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		ast, err := Parse(input)
		if err != nil {
			return // invalid syntax, skip
		}
		// Must not panic during compilation.
		rules, err := Compile(ast)
		if err != nil {
			return // compilation error, that's fine
		}
		// Also ensure evaluation doesn't panic with any compiled rules.
		ctx := EvalContext{
			InputRiskScore:    0.5,
			RequestModel:      "test",
			TenantDailyTokens: 1000,
		}
		_ = Evaluate(rules, ctx)
	})
}

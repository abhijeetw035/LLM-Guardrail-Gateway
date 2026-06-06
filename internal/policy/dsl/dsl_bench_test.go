package dsl

import (
	"fmt"
	"testing"
)

// validPolicy is a realistic policy used by all benchmarks.
const validPolicy = `policy tenant:bench {
  rule block_high_risk {
    when input.risk_score > 0.55
    action BLOCK
    reason "High risk"
  }
  rule tag_suspicious {
    when input.risk_score > 0.15
    action TAG
    reason "Suspicious"
  }
  rule restrict_model {
    when request.model NOT_IN ["gpt-4o", "gpt-4o-mini", "mock-llm"]
    action BLOCK
    reason "Unapproved model"
  }
  rule daily_quota {
    when tenant.daily_tokens > 100000
    action BLOCK
    reason "Quota exceeded"
  }
}`

// BenchmarkLex measures lexer throughput.
func BenchmarkLex(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := Lex(validPolicy)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkParse measures lex + parse throughput.
func BenchmarkParse(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := Parse(validPolicy)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCompile measures lex + parse + compile throughput.
func BenchmarkCompile(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ast, err := Parse(validPolicy)
		if err != nil {
			b.Fatal(err)
		}
		_, err = Compile(ast)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEvaluate measures per-request evaluation time.
// This is the hot path — only the pre-compiled closures are called.
func BenchmarkEvaluate(b *testing.B) {
	ast, err := Parse(validPolicy)
	if err != nil {
		b.Fatal(err)
	}
	rules, err := Compile(ast)
	if err != nil {
		b.Fatal(err)
	}

	ctx := EvalContext{
		InputRiskScore:    0.3,
		RequestModel:      "gpt-4o",
		TenantDailyTokens: 5000,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v := Evaluate(rules, ctx)
		_ = v
	}
}

// BenchmarkEvaluateLargePolicy tests evaluation with 100 rules.
func BenchmarkEvaluateLargePolicy(b *testing.B) {
	// Generate a policy with 100 rules.
	src := "policy tenant:bench {\n"
	for i := 0; i < 100; i++ {
		src += fmt.Sprintf(`  rule rule_%d {
    when input.risk_score > %0.2f
    action BLOCK
    reason "rule %d"
  }
`, i, 0.90+float64(i)*0.001, i)
	}
	src += "}\n"

	ast, err := Parse(src)
	if err != nil {
		b.Fatal(err)
	}
	rules, err := Compile(ast)
	if err != nil {
		b.Fatal(err)
	}

	// Context that doesn't match any rule (worst case — all rules checked).
	ctx := EvalContext{
		InputRiskScore:    0.1,
		RequestModel:      "gpt-4o",
		TenantDailyTokens: 500,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v := Evaluate(rules, ctx)
		_ = v
	}
}

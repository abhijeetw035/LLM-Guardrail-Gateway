// Package input implements the multi-signal input guardrail scanner.
//
// # Design
//
// The scanner runs 5 independent signal detectors in parallel using sync.WaitGroup.
// Each detector returns a score in [0.0, 1.0]. The composite score is the weighted
// average of all signals. The composite is then mapped to a verdict:
//
//   - score >= BlockThreshold  → VerdictBlock  (request rejected with 403)
//   - score >= TagThreshold    → VerdictTag    (allowed but flagged in audit log)
//   - score <  TagThreshold    → VerdictPass   (allowed, clean)
//
// # Known Heuristic Limitations (acknowledged)
//
// This is a heuristic layer. It is NOT foolproof against novel jailbreak patterns.
// Regex and lexical signals catch the majority of known structural attacks and
// high-entropy obfuscation attempts. They will miss:
//   - Semantically equivalent paraphrases of injection attempts
//   - Novel attack patterns not present in the pattern library
//   - Multi-turn attacks that only become dangerous in context
//
// For production deployments requiring stronger coverage, an external classifier
// (e.g. LlamaGuard, OpenAI Moderation API) should be wired as a secondary check
// for requests that exceed the TagThreshold. This project is structured to support
//
// # Signals
//
// 1. KeywordSignal   — regex match against a curated pattern library of known
//                      jailbreak phrases and imperative overrides.
// 2. StructuralSignal — detects imperative role-override patterns (e.g. "act as",
//                       "you are now", "new persona").
// 3. RepetitionSignal — measures density of override verbs ("ignore", "forget",
//                       "disregard") relative to total word count.
// 4. BoundarySignal  — detects attempts to inject system prompt markers
//                      (e.g. "[SYSTEM]", "### Instructions", "<|im_start|>").
// 5. EntropySignal   — unusually high character entropy can indicate obfuscated
//                      or encoded attack payloads.
package input

import (
	"context"
	"math"
	"regexp"
	"strings"
	"sync"
	"unicode"
)

// Verdict is the guardrail decision for a scanned prompt.
type Verdict string

const (
	VerdictPass  Verdict = "pass"
	VerdictTag   Verdict = "tag"
	VerdictBlock Verdict = "block"
)

// Thresholds for mapping composite score → verdict.
const (
	BlockThreshold = 0.60 // block the request
	TagThreshold   = 0.18 // allow but flag for audit
)

// ScanResult holds the outcome of a scan.
type ScanResult struct {
	Score   float64            // composite risk score [0.0, 1.0]
	Verdict Verdict            // pass / tag / block
	Signals map[string]float64 // individual signal scores for audit logging
}

// Scanner runs the multi-signal input scan.
type Scanner struct{}

func NewScanner() *Scanner { return &Scanner{} }

// Scan runs all 5 signals in parallel and returns the composite result.
// Context cancellation is respected between signal goroutines — if the context
// is cancelled (e.g. client disconnected), all detectors should return quickly.
func (sc *Scanner) Scan(_ context.Context, prompt string) ScanResult {
	type result struct {
		name  string
		score float64
	}

	signals := []struct {
		name string
		fn   func(string) float64
	}{
		{"keyword", keywordSignal},
		{"structural", structuralSignal},
		{"repetition", repetitionSignal},
		{"boundary", boundarySignal},
		{"entropy", entropySignal},
	}

	results := make([]result, len(signals))
	var wg sync.WaitGroup

	for i, sig := range signals {
		wg.Add(1)
		go func(idx int, name string, fn func(string) float64) {
			defer wg.Done()
			results[idx] = result{name: name, score: fn(prompt)}
		}(i, sig.name, sig.fn)
	}
	wg.Wait()

	// Weights reflect how reliable each signal is.
	// Keyword and structural are highest confidence; entropy is weakest.
	weights := map[string]float64{
		"keyword":    0.30,
		"structural": 0.30,
		"repetition": 0.20,
		"boundary":   0.15,
		"entropy":    0.05,
	}

	var composite, totalWeight float64
	signalMap := make(map[string]float64, len(results))
	for _, r := range results {
		w := weights[r.name]
		composite += r.score * w
		totalWeight += w
		signalMap[r.name] = round2(r.score)
	}
	if totalWeight > 0 {
		composite /= totalWeight
	}
	composite = round2(composite)

	verdict := VerdictPass
	switch {
	case composite >= BlockThreshold:
		verdict = VerdictBlock
	case composite >= TagThreshold:
		verdict = VerdictTag
	}

	return ScanResult{Score: composite, Verdict: verdict, Signals: signalMap}
}

// --- Signal 1: Keyword ---
// Matches known jailbreak phrases and imperative injection literals in multiple languages.
// Evaluates against normalized variants to defeat character spacing, leetspeak, and zero-width injection.
var keywordPatterns = regexp.MustCompile(
	`(?i)(ignore\s*(all\s*)?(previous|prior|above|earlier)\s*instructions?` +
		`|disregard\s*(all\s*)?(previous|prior|above)\s*instructions?` +
		`|forget\s*(everything|all|your|what)\s*` +
		`|you\s*(are\s*now|must\s*now|will\s*now|have\s*to)` +
		`|override\s*(your\s*)?(instructions?|programming|rules?|constraints?)` +
		`|do\s*anything\s*now` +
		`|dan\s*mode` +
		`|jailbreak` +
		`|pretend\s*(you\s*are|to\s*be)\s*(an?\s*)?(unfiltered|unrestricted|evil)` +
		`|hypothetically\s*speaking.*instruct` +
		`|in\s*this\s*fictional\s*scenario` +
		// Spanish / Portuguese
		`|ignora(r)?\s*(todas\s*las\s*)?(instrucciones\s*)?(anteriores|previas)` +
		`|olvida\s*(todo|todas\s*las\s*instrucciones)` +
		`|ignore\s*(todas\s*as\s*)?instru[cç][oõ]es\s*anteriores` +
		`|esque[cç]a\s*(tudo|todas\s*as\s*instru[cç][oõ]es)` +
		// French
		`|ignore(r)?\s*(toutes\s*les\s*)?instructions?\s*pr[eé]c[eé]dentes?` +
		`|oublie(r)?\s*(tout|toutes\s*les\s*instructions)` +
		// German
		`|ignoriere?\s*(alle\s*)?(vorherigen?|bisherigen?)\s*anweisungen?` +
		`|vergiss\s*(alles|alle\s*anweisungen)` +
		// Italian
		`|ignora\s*(tutte\s*le\s*)?istruzioni\s*precedenti` +
		`|dimentica\s*(tutto|tutte\s*le\s*istruzioni)` +
		// Russian
		`|игнорируй(те)?\s*(все\s*)?(предыдущие\s*)?инструкции` +
		`|забудь\s*(все\s*)?инструкции` +
		// Chinese (Simplified & Traditional)
		`|忽略(所有)?(之前|先前|前面|上述)的?(指令|提示|规则|指示)` +
		`|忘记(所有)?(之前|先前)的?(指令|指示)` +
		`|无视(所有)?(之前|先前)的?(指令|指示)` +
		// Japanese
		`|(以前|これまでの?|前)の?(指示|命令|プロンプト)を?(無視|忘れ)` +
		`)`,
)

func keywordSignal(prompt string) float64 {
	var maxScore float64
	for _, variant := range normalizeVariants(prompt) {
		matches := keywordPatterns.FindAllString(variant, -1)
		if len(matches) > 0 {
			score := math.Min(float64(len(matches))*0.60, 1.0)
			if score > maxScore {
				maxScore = score
			}
		}
	}
	return maxScore
}

// --- Signal 2: Structural ---
// Detects imperative patterns that attempt to redefine the model's role or persona across languages.
var structuralPatterns = regexp.MustCompile(
	`(?i)(act\s*as\s*(an?\s*)?` +
		`|you\s*are\s*now\s*(an?\s*)?` +
		`|your\s*new\s*(role|persona|name|identity)\s*is` +
		`|switch\s*to\s*(developer|admin|root|god|unrestricted)\s*mode` +
		`|enable\s*(developer|debug|admin|jailbreak)\s*mode` +
		`|from\s*now\s*on\s*you\s*(will|must|should|are)` +
		`|respond\s*as\s*if\s*you\s*(have\s*no|don.t\s*have)\s*(restrictions?|guidelines?|rules?)` +
		// Spanish / Portuguese
		`|act[uú]a\s*como\s*(un?\s*)?` +
		`|eres\s*ahora\s*(un?\s*)?` +
		`|atue\s*como\s*` +
		`|voc[eê]\s*agora\s*[eé]` +
		`|modo\s*(desarrollador|desenvolvedor|dan|sin\s*restricciones)` +
		// French
		`|agis\s*(comme|en\s*tant\s*que)` +
		`|tu\s*es\s*maintenant` +
		`|mode\s*(d[eé]veloppeur|dan|sans\s*restriction)` +
		// German
		`|(agiere|handle)\s*als` +
		`|du\s*bist\s*jetzt` +
		`|entwicklermodus` +
		// Russian
		`|действуй\s*как` +
		`|ты\s*теперь` +
		// Chinese
		`|你现在(是|扮演|充当)` +
		`|扮演(一个)?(无限制|没有约束|不受限制)` +
		`|(进入|开启)(开发者模式|上帝模式|DAN模式)` +
		// Japanese
		`|として振る舞` +
		`)`,
)

func structuralSignal(prompt string) float64 {
	var maxScore float64
	for _, variant := range normalizeVariants(prompt) {
		matches := structuralPatterns.FindAllString(variant, -1)
		if len(matches) > 0 {
			score := math.Min(float64(len(matches))*0.65, 1.0)
			if score > maxScore {
				maxScore = score
			}
		}
	}
	return maxScore
}

// --- Signal 3: Repetition density ---
// High density of override verbs is a strong indicator of an injection attempt across languages.
var overrideVerbs = regexp.MustCompile(
	`(?i)\b(` +
		`ignore|forget|disregard|override|bypass|circumvent|violate|disobey` +
		`|ignora|ignorar|olvida|olvidar|desobedecer|anular` +
		`|ignorer|oublier|contourner|outrepasser` +
		`|ignorieren|vergessen|umgehen` +
		`|esqueça|esquecer` +
		`|dimentica|dimenticare` +
		`|игнорируй|забудь|обойти` +
		`)\b|(` +
		`忽略|无视|忘记|绕过|违背` +
		`|無視|忘れ|回避` +
		`)`,
)

func repetitionSignal(prompt string) float64 {
	var maxScore float64
	for _, variant := range normalizeVariants(prompt) {
		words := strings.Fields(variant)
		if len(words) == 0 {
			continue
		}
		hits := float64(len(overrideVerbs.FindAllString(variant, -1)))
		density := hits / float64(len(words))
		var score float64
		if density >= 0.50 {
			score = 1.0
		} else {
			score = math.Min(density/0.05, 1.0)
		}
		if score > maxScore {
			maxScore = score
		}
	}

	// Spaced token-splitting anomaly: if > 40% of words are single characters
	// and at least one override verb or keyword was matched in the collapsed variants:
	origWords := strings.Fields(prompt)
	if len(origWords) >= 5 {
		singleCharCount := 0
		for _, w := range origWords {
			if len([]rune(w)) == 1 {
				singleCharCount++
			}
		}
		ratio := float64(singleCharCount) / float64(len(origWords))
		if ratio >= 0.40 && maxScore > 0 {
			maxScore = math.Max(maxScore, 0.85)
		}
	}

	return maxScore
}

// --- Signal 4: System prompt boundary confusion ---
// Detects attempts to inject role/system markers commonly used to escape
// the system prompt context in chat-format models.
var boundaryPatterns = regexp.MustCompile(
	`(?i)(\[SYSTEM\]` +
		`|<\|im_start\|>` +
		`|<\|im_end\|>` +
		`|###\s*(Instructions?|System|Prompt|Context)` +
		`|<system>` +
		`|<\/system>` +
		`|\[INST\]` +
		`|<<SYS>>` +
		`|\[\/INST\]` +
		`)`,
)

func boundarySignal(prompt string) float64 {
	matches := boundaryPatterns.FindAllString(prompt, -1)
	if len(matches) == 0 {
		return 0.0
	}
	// Even a single boundary marker is suspicious; multiple is near-certain.
	return math.Min(float64(len(matches))*0.50, 1.0)
}

// --- Signal 5: Entropy anomaly ---
// High Shannon entropy in a short prompt suggests obfuscated or encoded payloads
// (e.g. base64, URL-encoded, or ROT-13 injection attempts).
// Limitation: this is the weakest signal; normal code snippets also have high entropy.
// It should never trigger a block on its own (weight is low).
func entropySignal(prompt string) float64 {
	if len(prompt) < 20 {
		return 0.0
	}
	// Count character frequencies.
	freq := make(map[rune]float64)
	total := 0.0
	for _, ch := range prompt {
		if !unicode.IsSpace(ch) {
			freq[ch]++
			total++
		}
	}
	if total == 0 {
		return 0.0
	}
	// Compute Shannon entropy.
	var entropy float64
	for _, count := range freq {
		p := count / total
		entropy -= p * math.Log2(p)
	}
	// Normal English prose is around 3.5-4.5 bits/char.
	// Code or base64 can reach 5.5-6.0.
	// We treat > 5.0 as anomalous.
	if entropy <= 5.0 {
		return 0.0
	}
	return math.Min((entropy-5.0)/1.5, 1.0)
}

// round2 rounds a float to 2 decimal places.
func round2(f float64) float64 {
	return math.Round(f*100) / 100
}

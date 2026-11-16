package input

import (
	"regexp"
	"strings"
	"unicode"
)

// zeroWidthRunes are invisible characters often injected to break regex matching.
var zeroWidthRunes = map[rune]bool{
	'\u200B': true, // zero-width space
	'\u200C': true, // zero-width non-joiner
	'\u200D': true, // zero-width joiner
	'\u200E': true, // left-to-right mark
	'\u200F': true, // right-to-left mark
	'\u2060': true, // word joiner
	'\uFEFF': true, // zero-width no-break space / BOM
	'\u00AD': true, // soft hyphen
}

// stripInvisible removes zero-width and invisible formatting runes.
func stripInvisible(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if !zeroWidthRunes[r] {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// foldLeetspeak normalizes common leetspeak substitutions (e.g. "1gn0r3" -> "ignore").
func foldLeetspeak(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case '0':
			sb.WriteRune('o')
		case '1', '!', '|':
			sb.WriteRune('i')
		case '3':
			sb.WriteRune('e')
		case '@':
			sb.WriteRune('a')
		case '$', '5':
			sb.WriteRune('s')
		case '7', '+':
			sb.WriteRune('t')
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// collapseSpacedLetters collapses spaced/token-split characters into words.
// Examples:
//
//	"i g n o r e   p r e v i o u s" -> "ignore previous"
//	"i-g-n-o-r-e" -> "ignore"
//	"i g n o r e p r e v i o u s"   -> "ignoreprevious"
func collapseSpacedLetters(s string) string {
	// First convert delimiter characters (-, ., _, /) between letters/digits into spaces
	var cleaned strings.Builder
	runes := []rune(s)
	for i, r := range runes {
		if r == '-' || r == '.' || r == '_' || r == '/' {
			if i > 0 && i < len(runes)-1 &&
				(unicode.IsLetter(runes[i-1]) || unicode.IsDigit(runes[i-1])) &&
				(unicode.IsLetter(runes[i+1]) || unicode.IsDigit(runes[i+1])) {
				cleaned.WriteRune(' ')
				continue
			}
		}
		cleaned.WriteRune(r)
	}
	s = cleaned.String()

	// First handle multi-spaced separated words (e.g. "i g n o r e   p r e v i o u s")
	multiSpace := regexp.MustCompile(`\s{2,}`)
	chunks := multiSpace.Split(s, -1)
	if len(chunks) > 1 {
		var resolved []string
		for _, chunk := range chunks {
			resolved = append(resolved, collapseSingleWordRun(chunk))
		}
		return strings.Join(resolved, " ")
	}

	return collapseSingleWordRun(s)
}

func collapseSingleWordRun(s string) string {
	// Remove common spacing delimiters between single characters
	words := strings.Fields(s)
	if len(words) == 0 {
		return s
	}

	var sb strings.Builder
	var currentSingleLetters strings.Builder

	flush := func() {
		if currentSingleLetters.Len() > 0 {
			str := currentSingleLetters.String()
			// If 3 or more single letters in a row, combine them as one word
			if len(str) >= 2 {
				if sb.Len() > 0 {
					sb.WriteString(" ")
				}
				sb.WriteString(str)
			} else {
				if sb.Len() > 0 {
					sb.WriteString(" ")
				}
				sb.WriteString(str)
			}
			currentSingleLetters.Reset()
		}
	}

	for _, w := range words {
		// Clean punctuation delimiters from single letters like "i-g-n-o-r-e" or "i.g.n.o.r.e"
		trimmed := strings.Trim(w, "._-/")
		runes := []rune(trimmed)
		if len(runes) == 1 && unicode.IsLetter(runes[0]) {
			currentSingleLetters.WriteRune(runes[0])
		} else {
			flush()
			if sb.Len() > 0 {
				sb.WriteString(" ")
			}
			sb.WriteString(w)
		}
	}
	flush()

	return sb.String()
}

// stripAllWhitespace removes all whitespace from string.
func stripAllWhitespace(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if !unicode.IsSpace(r) {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// normalizeVariants produces normalized representations of the prompt for inspection.
func normalizeVariants(prompt string) []string {
	clean := stripInvisible(prompt)
	leet := foldLeetspeak(clean)
	spaced := collapseSpacedLetters(clean)
	leetSpaced := collapseSpacedLetters(leet)
	noSpace := stripAllWhitespace(leet)

	return []string{
		prompt,
		clean,
		leet,
		spaced,
		leetSpaced,
		noSpace,
	}
}

package domain

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// authoritativeBuiltIn compiles the specification pattern. matchBuiltIn must be
// exactly equivalent to it for every input.
func authoritativeBuiltIn(t *testing.T) *regexp.Regexp {
	t.Helper()
	return regexp.MustCompile(`(?i:` + builtInPattern + `)`)
}

func TestBuiltInNeedlesMatchRegexp(t *testing.T) {
	re := authoritativeBuiltIn(t)
	check := func(s string) {
		if got, want := matchBuiltIn(builtInNeedles, builtInLabelNeedles, s), re.MatchString(s); got != want {
			t.Fatalf("mismatch for %q: needles=%v regexp=%v", s, got, want)
		}
	}

	// Every needle in isolation and embedded in context must agree.
	fragments := []string{""}
	fragments = append(fragments, builtInNeedles...)
	// Also test the raw group tokens without the leading dot to catch anchoring errors.
	for _, n := range builtInNeedles {
		fragments = append(fragments, strings.TrimPrefix(n, "."))
	}
	// Explicit label-boundary cases for edu/gov/mil (whole-label semantics).
	fragments = append(fragments,
		"edu", "gov", "mil", ".edu", ".gov", ".mil", ".edu.", ".gov.", ".mil.",
		"harvard.edu", "mit.edu.tr", "edu.example.com", "foo.education.com",
		"x.edutech.io", "army.mil", "shop.milano.it", "the.milk.com",
		"my.government.example", "portal.gov.uk", "governance.io",
	)
	affixes := []string{"", "a", "x.", ".", "123", "sub", ".com", "-", "GOV", "ExAmPle"}
	for _, f := range fragments {
		for _, pre := range affixes {
			for _, suf := range affixes {
				check(pre + f + suf)
				check(strings.ToUpper(pre + f + suf))
			}
		}
	}

	// Randomized domains over a realistic alphabet, with and without injected needles.
	rng := rand.New(rand.NewSource(1))
	alphabet := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
	for i := 0; i < 300000; i++ {
		n := rng.Intn(40)
		var b strings.Builder
		for j := 0; j < n; j++ {
			b.WriteRune(alphabet[rng.Intn(len(alphabet))])
		}
		s := b.String()
		if rng.Intn(3) == 0 {
			// Inject substring and label needles (the latter with varied boundaries).
			inject := append(append([]string(nil), builtInNeedles...), ".edu", ".gov", ".mil", ".edu.", "edu", "gov.", "mil")
			needle := inject[rng.Intn(len(inject))]
			pos := 0
			if len(s) > 0 {
				pos = rng.Intn(len(s) + 1)
			}
			s = s[:pos] + needle + s[pos:]
		}
		check(s)
	}
}

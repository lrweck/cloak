package cloak_test

import (
	"errors"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strings"
	"testing"
)

// Plain testing on purpose: cloak has no dependencies and never will, so this does not pull
// in a test library to check the file that advertises the dependency count.
//
// The other README tests check what each snippet claims. They are written against the
// intent, so a snippet can stop compiling while the behaviour it describes still holds —
// which is how two blocks kept a stray comma and a missing paren for a long time.
//
// This one reads the file instead, so the text cannot drift from the Go grammar. It
// closes the class rather than the two instances.

var (
	goBlock = regexp.MustCompile("(?s)```go\n(.*?)```")
	pkgMark = regexp.MustCompile(`(?m)^\s*//\s*package\s+\w+\s*$`)
	// bench/compare is a separate module, so `go test ./...` from the root skips it.
	// Reading it by path is what keeps its snippets honest from the library's own CI.
	readmeIn = []string{"README.md", "bench/README.md", "bench/compare/README.md"}
)

// prelude supplies the names a fragment may use, so the check is about syntax and not
// about whether the snippet restates its own imports.
const prelude = `package main

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/lrweck/cloak"
)

var (
	_ = os.Stdout
	_ = context.Background
	_ = strings.Contains
	_ = time.Now
	_ = slog.LevelInfo
)

`

// parseable reports whether a snippet is valid Go in any of the shapes a README uses:
// statements, top-level declarations, or either of those split across `// package`
// markers when a block shows two packages at once.
func parseable(snippet string) error {
	parts := pkgMark.Split(snippet, -1)
	if len(parts) > 1 {
		for _, part := range parts {
			if err := parses(part); err != nil {
				return err
			}
		}
		return nil
	}
	return parses(snippet)
}

var errNotGo = errors.New("nao parseia")

func parses(snippet string) error {
	// A block that brings its own `package` clause and imports is a whole program:
	// prepending the prelude would give it two package clauses.
	if strings.HasPrefix(strings.TrimSpace(snippet), "package ") {
		if _, err := parser.ParseFile(token.NewFileSet(), "whole.go", snippet, parser.AllErrors); err == nil {
			return nil
		}
	}
	if _, err := parser.ParseFile(token.NewFileSet(), "a.go",
		prelude+"func _() {\n"+snippet+"\n}", parser.AllErrors); err == nil {
		return nil
	}
	if _, err := parser.ParseFile(token.NewFileSet(), "b.go",
		prelude+snippet, parser.AllErrors); err == nil {
		return nil
	}
	// A method cannot be declared on a function-local type, and a bare `func Name(...)`
	// is not a statement at all, so a block that mixes declarations with the call using
	// them needs its two halves judged separately.
	if i := strings.Index(snippet, "\n\n"); i > 0 {
		_, declErr := parser.ParseFile(token.NewFileSet(), "c.go",
			prelude+snippet[:i], parser.AllErrors)
		_, stmtErr := parser.ParseFile(token.NewFileSet(), "d.go",
			prelude+"func _() {\n"+snippet[i:]+"\n}", parser.AllErrors)
		if declErr == nil && stmtErr == nil {
			return nil
		}
	}
	return errNotGo
}

// A bare expression is a legitimate thing to show, but it is not a Go program, so the
// ```go fence overstates it.
var notAProgram = regexp.MustCompile(`(?m)^"[a-z_]+", `)

// go/parser accepts a trailing comma on the same line as the closing bracket, which the
// compiler rejects with "unexpected ) at end of statement". The spec only allows it when
// the bracket is on its own line, so a comma-then-bracket with nothing between them and
// no newline is always a mistake. This catches what the parser lets through, and it
// cannot fire on valid Go, where the legal form always has the newline.
var sameLineComma = regexp.MustCompile(`,[ \t]*\)`)

// TestReadmeGoBlocksAreWellFormed checks the shape of the Go in the READMEs, not that it
// type-checks. It cannot: the snippets are fragments, and resolving cloak's own types
// would need a compiler invocation per block. What it does guarantee is that no block is
// structurally broken — a missing paren, a stray comma, a declaration spliced into the
// statement that uses it — which is how two of them stayed broken for as long as they did.
func TestReadmeGoBlocksAreWellFormed(t *testing.T) {
	t.Parallel()

	for _, path := range readmeIn {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("abrindo %s: %v", path, err)
			}

			var n int
			for _, m := range goBlock.FindAllStringSubmatch(string(src), -1) {
				n++
				snippet := m[1]

				if notAProgram.MatchString(snippet) {
					t.Errorf("bloco %d e uma expressao solta, nao um programa Go:\n%s", n, snippet)
					continue
				}
				if loc := sameLineComma.FindStringIndex(snippet); loc != nil {
					line := strings.Count(string(src)[:strings.Index(string(src), snippet)], "\n") + 1
					t.Errorf("bloco %d (linha %d): virgula antes do ) na mesma linha, que o compilador rejeita:\n%s",
						n, line, snippet)
					continue
				}
				if err := parseable(snippet); err != nil {
					line := strings.Count(string(src)[:strings.Index(string(src), snippet)], "\n") + 1
					t.Errorf("bloco %d (linha %d) nao compila:\n%s", n, line, snippet)
				}
			}
			if n == 0 {
				t.Logf("%s: nenhum bloco go, nada a checar", path)
				return
			}
			t.Logf("%s: %d blocos go checados", path, n)
		})
	}
}

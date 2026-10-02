package cloak_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/lrweck/cloak"
)

// The package doc promises one shape for every option that takes a Masker: it comes
// first. A convention nobody checks is one the next option breaks, so this reads the
// real signatures instead of trusting them.
func TestMaskerIsAlwaysTheFirstArgument(t *testing.T) {
	for _, sig := range optionSignatures(t) {
		idx := -1
		for i, a := range sig.args {
			if a.typeName == "Masker" {
				idx = i
				break
			}
		}
		switch {
		case idx < 0:
			// Declares no Masker: WithRedactedValue, WithValueFunc, WithType's
			// variadic form. The rule is about the fixed parameter.
		case idx == 0:
		default:
			t.Errorf("%s declares its Masker as argument %d (%s), not first\n"+
				"the package doc says every option that takes a Masker takes it first",
				sig.name, idx+1, sig.args[idx].typeName)
		}
	}
}

// WithType takes a variadic Masker and nothing else, so "first" is trivially true for
// it. Asserting that separately keeps the check above honest about what it skips.
func TestWithTypeTakesOnlyMaskers(t *testing.T) {
	for _, sig := range optionSignatures(t) {
		if sig.name != "WithType" {
			continue
		}
		if len(sig.args) != 1 || sig.args[0].typeName != "...Masker" {
			t.Fatalf("WithType takes %+v, want a single variadic Masker", sig.args)
		}
		return
	}
	t.Fatal("WithType not found")
}

// The premise of the check above: Masker is a func type, not an interface or an alias.
// Were it ever changed, the AST walk would keep passing while meaning nothing.
func TestMaskerIsAFuncType(t *testing.T) {
	if k := reflect.TypeFor[cloak.Masker]().Kind(); k != reflect.Func {
		t.Fatalf("Masker is a %s, not a func: the convention checks assume a func type", k)
	}
}

type param struct {
	name     string
	typeName string
}

type signature struct {
	name string
	args []param
}

// optionSignatures parses the package's own source. Reflection cannot answer this: a
// variadic parameter and a plain one have the same reflect.Type, and telling them apart
// is exactly what distinguishing WithType from WithKeys requires.
func optionSignatures(t *testing.T) []signature {
	t.Helper()

	// parser.ParseDir was deprecated in Go 1.25 and the suggested replacement,
	// golang.org/x/tools/go/packages, is a dependency this library does not have. Reading
	// the directory and parsing each file is the same walk without either.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}

	var out []signature
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !strings.HasPrefix(fn.Name.Name, "With") || fn.Recv != nil {
				continue
			}
			sig := signature{name: fn.Name.Name}
			if fn.Type.Params != nil {
				for _, field := range fn.Type.Params.List {
					typ := exprName(field.Type)
					names := make([]string, len(field.Names))
					for i, n := range field.Names {
						names[i] = n.Name
					}
					if len(names) == 0 {
						sig.args = append(sig.args, param{typeName: typ})
						continue
					}
					for _, n := range names {
						sig.args = append(sig.args, param{name: n, typeName: typ})
					}
				}
			}
			out = append(out, sig)
		}
	}
	if len(out) < 15 {
		t.Fatalf("found only %d With* functions, expected the full option set", len(out))
	}
	return out
}

func exprName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.Ellipsis:
		return "..." + exprName(v.Elt)
	case *ast.StarExpr:
		return "*" + exprName(v.X)
	case *ast.FuncType:
		return "func"
	case *ast.SelectorExpr:
		return v.Sel.Name
	case *ast.ArrayType:
		return "[]" + exprName(v.Elt)
	case *ast.MapType:
		return "map"
	case *ast.InterfaceType:
		return "interface"
	default:
		return "?"
	}
}

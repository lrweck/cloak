package cloak

import (
	"fmt"
	"log/slog"
	"testing"
)

type user struct {
	Email string
	CPF   string
	Tags  []string
}

func TestBytes(t *testing.T) {
	for _, s := range []any{
		[]byte("payload"),
		[]byte{1, 2, 3, 4, 5, 6, 7, 8},
		&user{Email: "a@b.com"},
		[]*user{{Email: "a@b.com", CPF: "529.982.247-25"}},
		map[string]any{"u": user{Email: "a@b.com"}},
		user{Tags: []string{"a@b.com"}},
	} {
		r := fmt.Sprintf("%+v", s)
		m, _ := maskStringProbe(r)
		fmt.Printf("%-32T -> %-46q masked=%q\n", s, r, m)
	}
}

func maskStringProbe(s string) (string, bool) {
	h := New(slog.NewTextHandler(nil, nil), WithDefaultPIIValues()).(*Handler)
	return h.maskString(s)
}

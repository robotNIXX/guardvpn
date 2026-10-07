package process

import "testing"

func BenchmarkList(b *testing.B) {
	l := NewLister()
	for b.Loop() {
		ps, err := l.List()
		if err != nil || len(ps) == 0 {
			b.Fatal(err)
		}
	}
}

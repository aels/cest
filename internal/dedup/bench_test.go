package dedup

import (
	"strconv"
	"testing"
)

func BenchmarkAddUnique(b *testing.B) {
	f := New(100000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Add("host-" + strconv.Itoa(i) + ".example.com")
	}
}

func BenchmarkAddDuplicate(b *testing.B) {
	f := New(100000)
	f.Add("repeated.example.com")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Add("repeated.example.com")
	}
}

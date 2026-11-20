package sorter

import (
	"net/http"
	"strings"
	"testing"
)

func benchSorter() *Sorter {
	return &Sorter{rules: []compiledRule{
		{path: "wordpress", literal: []byte("wp-content")},
		{path: "wordpress", literal: []byte("X-Powered-By: WordPress")},
		{path: "magento", literal: []byte("Magento_")},
		{path: "shops", literal: []byte(`class="cart"`)},
		{path: "nextjs", literal: []byte("__next_f")},
	}}
}

func benchResponse() responseData {
	body := []byte(strings.Repeat("<div>", 2000) + "id=\"__next_f\"" + strings.Repeat("</div>", 2000))
	header := http.Header{
		"Content-Type":  {"text/html; charset=utf-8"},
		"Server":        {"nginx"},
		"X-Powered-By":  {"Next.js"},
		"Cache-Control": {"no-cache"},
		"Set-Cookie":    {"a=1", "b=2"},
	}
	return responseData{body: body, header: header}
}

func BenchmarkMatch(b *testing.B) {
	s := benchSorter()
	resp := benchResponse()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.match(resp)
	}
}

func BenchmarkHeaderBlob(b *testing.B) {
	resp := benchResponse()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = headerBlob(resp.header)
	}
}

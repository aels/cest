package ctstream

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func put16(b *bytes.Buffer, v []byte) {
	_ = binary.Write(b, binary.BigEndian, uint16(len(v)))
	b.Write(v)
}

func put24(b *bytes.Buffer, v []byte) {
	b.Write([]byte{byte(len(v) >> 16), byte(len(v) >> 8), byte(len(v))})
	b.Write(v)
}

func leafFixture(typ uint16, der []byte) []byte {
	var b bytes.Buffer
	b.Write([]byte{0, 0})
	b.Write(make([]byte, 8))
	_ = binary.Write(&b, binary.BigEndian, typ)
	if typ == entryPrecert {
		b.Write(make([]byte, 32))
	}
	put24(&b, der)
	put16(&b, []byte{1, 2})
	return b.Bytes()
}

func tileFixture(typ uint16, der []byte) []byte {
	var b bytes.Buffer
	b.Write(make([]byte, 8))
	_ = binary.Write(&b, binary.BigEndian, typ)
	if typ == entryPrecert {
		b.Write(make([]byte, 32))
		put24(&b, der)
		put16(&b, nil)
		put24(&b, []byte{0x30, 0})
		put16(&b, make([]byte, 32))
	} else {
		put24(&b, der)
		put16(&b, nil)
		put16(&b, make([]byte, 32))
	}
	return b.Bytes()
}

func TestParseLeafInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  uint16
		tbs  bool
	}{
		{"certificate", entryX509, false},
		{"precertificate", entryPrecert, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := []byte{0x30, 3, 1, 2, 3}
			fixture := leafFixture(tc.typ, want)
			got, isTBS, err := parseLeafInput(fixture)
			if err != nil || isTBS != tc.tbs || !bytes.Equal(got, want) {
				t.Fatalf("got %x, tbs=%v, err=%v", got, isTBS, err)
			}
			for i := range fixture {
				if _, _, err := parseLeafInput(fixture[:i]); err == nil {
					t.Fatalf("accepted truncation at %d", i)
				}
			}
		})
	}
}

func TestParseLeafInputRejectsMalformed(t *testing.T) {
	unknown := leafFixture(2, []byte{1})
	if _, _, err := parseLeafInput(unknown); err == nil {
		t.Fatal("accepted unknown entry type")
	}
	trailing := append(leafFixture(entryX509, []byte{1}), 0)
	if _, _, err := parseLeafInput(trailing); err == nil {
		t.Fatal("accepted trailing byte")
	}
	wrongVersion := leafFixture(entryX509, []byte{1})
	wrongVersion[0] = 1
	if _, _, err := parseLeafInput(wrongVersion); err == nil {
		t.Fatal("accepted unknown version")
	}
}

func TestParseTileData(t *testing.T) {
	cert := tileFixture(entryX509, []byte{0x30, 0})
	precert := tileFixture(entryPrecert, []byte{0x30, 1, 0})
	fixture := append(cert, precert...)
	got, err := parseTileData(fixture, 2)
	if err != nil || len(got) != 2 {
		t.Fatalf("len=%d err=%v", len(got), err)
	}
	if got[0].isTBS || !got[1].isTBS {
		t.Fatalf("wrong entry kinds: %+v", got)
	}
	for i := range fixture {
		if _, err := parseTileData(fixture[:i], 2); err == nil {
			t.Fatalf("accepted truncation at %d", i)
		}
	}
}

func TestParseTileDataBounds(t *testing.T) {
	one := tileFixture(entryX509, []byte{1})
	if _, err := parseTileData(append(append([]byte(nil), one...), one...), 1); err == nil {
		t.Fatal("accepted more entries than tile width")
	}
	unknown := tileFixture(entryX509, []byte{1})
	unknown[9] = 2
	if _, err := parseTileData(unknown, 1); err == nil {
		t.Fatal("accepted unknown entry type")
	}
	if _, err := parseTileData(nil, 1); err == nil {
		t.Fatal("accepted empty tile")
	}
}

func FuzzParseLeafInput(f *testing.F) {
	f.Add(leafFixture(entryX509, []byte{0x30, 0}))
	f.Fuzz(func(t *testing.T, b []byte) { _, _, _ = parseLeafInput(b) })
}

func FuzzParseTileData(f *testing.F) {
	f.Add(tileFixture(entryPrecert, []byte{0x30, 0}))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = parseTileData(b, tileWidth) })
}

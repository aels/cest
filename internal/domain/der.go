package domain

import (
	"encoding/asn1"
	"unicode/utf16"
	"unicode/utf8"
)

type derReader struct {
	data []byte
	off  int
}

func newDER(b []byte) *derReader        { return &derReader{data: b} }
func (r *derReader) empty() bool        { return r.off == len(r.data) }
func (r *derReader) peek(tag byte) bool { return r.off < len(r.data) && r.data[r.off] == tag }

func (r *derReader) read(tag byte) ([]byte, error) {
	_, body, err := r.readTLV(tag)
	return body, err
}
func (r *derReader) readRaw(tag byte) ([]byte, error) {
	start := r.off
	_, _, err := r.readTLV(tag)
	if err != nil {
		return nil, err
	}
	return r.data[start:r.off], nil
}
func (r *derReader) readTLV(tag byte) ([]byte, []byte, error) {
	start := r.off
	if r.off >= len(r.data) || r.data[r.off] != tag {
		return nil, nil, ErrMalformedDER
	}
	r.off++
	if r.off >= len(r.data) {
		return nil, nil, ErrMalformedDER
	}
	first := r.data[r.off]
	r.off++
	length := 0
	if first&0x80 == 0 {
		length = int(first)
	} else {
		n := int(first & 0x7f)
		if n == 0 || n > 4 || r.off+n > len(r.data) || r.data[r.off] == 0 {
			return nil, nil, ErrMalformedDER
		}
		for i := 0; i < n; i++ {
			length = length<<8 | int(r.data[r.off+i])
		}
		if length < 128 {
			return nil, nil, ErrMalformedDER
		}
		r.off += n
	}
	if length < 0 || length > len(r.data)-r.off {
		return nil, nil, ErrMalformedDER
	}
	body := r.data[r.off : r.off+length]
	r.off += length
	return r.data[start:r.off], body, nil
}

var oidCN = asn1.ObjectIdentifier{2, 5, 4, 3}
var oidSAN = asn1.ObjectIdentifier{2, 5, 29, 17}

func parseSubject(body []byte) (string, error) {
	r := newDER(body)
	cn := ""
	for !r.empty() {
		set, err := r.read(0x31)
		if err != nil {
			return "", err
		}
		sr := newDER(set)
		for !sr.empty() {
			atv, e := sr.read(0x30)
			if e != nil {
				return "", e
			}
			ar := newDER(atv)
			oidBody, e := ar.read(0x06)
			if e != nil {
				return "", e
			}
			oid, e := decodeOID(oidBody)
			if e != nil {
				return "", e
			}
			if ar.empty() {
				return "", ErrMalformedDER
			}
			tag := ar.data[ar.off]
			value, e := ar.read(tag)
			if e != nil || !ar.empty() {
				return "", ErrMalformedDER
			}
			if oid.Equal(oidCN) && cn == "" {
				cn, e = decodeDirectoryString(tag, value)
				if e != nil {
					return "", e
				}
			}
		}
	}
	return cn, nil
}

func parseExtensions(explicit []byte) ([]string, error) {
	er := newDER(explicit)
	seq, err := er.read(0x30)
	if err != nil || !er.empty() {
		return nil, ErrMalformedDER
	}
	r := newDER(seq)
	var names []string
	foundSAN := false
	for !r.empty() {
		ext, e := r.read(0x30)
		if e != nil {
			return nil, e
		}
		xr := newDER(ext)
		oidBody, e := xr.read(0x06)
		if e != nil {
			return nil, e
		}
		oid, e := decodeOID(oidBody)
		if e != nil {
			return nil, e
		}
		if xr.peek(0x01) {
			critical, ce := xr.read(0x01)
			if ce != nil || len(critical) != 1 || (critical[0] != 0x00 && critical[0] != 0xff) {
				return nil, ErrMalformedDER
			}
		}
		value, e := xr.read(0x04)
		if e != nil || !xr.empty() {
			return nil, ErrMalformedDER
		}
		if oid.Equal(oidSAN) {
			if foundSAN {
				return nil, ErrMalformedDER
			}
			foundSAN = true
			names, e = parseGeneralNames(value)
			if e != nil {
				return nil, e
			}
		}
	}
	return names, nil
}

func parseGeneralNames(der []byte) ([]string, error) {
	r := newDER(der)
	seq, err := r.read(0x30)
	if err != nil || !r.empty() {
		return nil, ErrMalformedDER
	}
	gr := newDER(seq)
	var names []string
	for !gr.empty() {
		tag := gr.data[gr.off]
		// GeneralName tags [0] through [8]. Constructedness is fixed by the ASN.1 type.
		if tag != 0xa0 && tag != 0x81 && tag != 0x82 && tag != 0xa3 && tag != 0xa4 && tag != 0xa5 && tag != 0x86 && tag != 0x87 && tag != 0x88 {
			return nil, ErrMalformedDER
		}
		value, e := gr.read(tag)
		if e != nil {
			return nil, e
		}
		if tag == 0x82 {
			if !utf8.Valid(value) {
				return nil, ErrMalformedDER
			}
			names = append(names, string(value))
		}
	}
	return names, nil
}

func decodeOID(body []byte) (asn1.ObjectIdentifier, error) {
	// Re-wrap the already strictly bounded body; encoding/asn1 validates OID arcs.
	if len(body) == 0 || len(body) > 127 {
		return nil, ErrMalformedDER
	}
	der := append([]byte{0x06, byte(len(body))}, body...)
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(der, &oid)
	if err != nil || len(rest) != 0 {
		return nil, ErrMalformedDER
	}
	return oid, nil
}

func decodeDirectoryString(tag byte, b []byte) (string, error) {
	switch tag {
	case 0x0c, 0x13, 0x14, 0x16: // UTF8, Printable, T61, IA5
		if tag == 0x0c && !utf8.Valid(b) {
			return "", ErrMalformedDER
		}
		return string(b), nil
	case 0x1e: // BMPString
		if len(b)%2 != 0 {
			return "", ErrMalformedDER
		}
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
		}
		for _, v := range u {
			if v >= 0xd800 && v <= 0xdfff {
				return "", ErrMalformedDER
			}
		}
		return string(utf16.Decode(u)), nil
	default:
		return "", ErrMalformedDER
	}
}

package config

import (
	"bytes"
	"testing"
)

func TestParseDefaultsAndStreams(t *testing.T) {
	cfg, done, err := Parse([]string{"--stream", "wp:wp-content", "-s", "shop:cart", "--code", "303,404,303,200"}, &bytes.Buffer{})
	if err != nil || done {
		t.Fatalf("parse: done=%v err=%v", done, err)
	}
	if cfg.Port != 4949 || cfg.Threads != 2000 || len(cfg.Streams) != 2 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if len(cfg.SuccessCodes) != 2 || cfg.SuccessCodes[0] != 303 || cfg.SuccessCodes[1] != 404 {
		t.Fatalf("success codes = %v", cfg.SuccessCodes)
	}
}

func TestParseAllowsDuplicateStreamPath(t *testing.T) {
	cfg, _, err := Parse([]string{"-s", "wp:a", "--stream", "wp:b"}, &bytes.Buffer{})
	if err != nil || len(cfg.Streams) != 2 {
		t.Fatalf("streams=%v err=%v", cfg.Streams, err)
	}
}

func TestParseRejectsOldSortFlag(t *testing.T) {
	_, _, err := Parse([]string{"--sort", "wp:a"}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseRejectsBadCode(t *testing.T) {
	for _, value := range []string{"", "99", "600", "x", "303,"} {
		if _, _, err := Parse([]string{"--code", value}, &bytes.Buffer{}); err == nil {
			t.Errorf("code %q accepted", value)
		}
	}
}

func TestParseRejectsBadRegex(t *testing.T) {
	_, _, err := Parse([]string{"--filter", "["}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNoFilterDoesNotDisableCustom(t *testing.T) {
	cfg, _, err := Parse([]string{"--nofilter", "--filter", "example"}, &bytes.Buffer{})
	if err != nil || cfg.Filter != "example" {
		t.Fatal(err)
	}
}

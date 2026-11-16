package config

import (
	"bytes"
	"testing"
)

func TestParseDefaultsAndSort(t *testing.T) {
	cfg, done, err := Parse([]string{"--sort", "wp:wp-content", "-s", "shop:cart"}, &bytes.Buffer{})
	if err != nil || done {
		t.Fatalf("parse: done=%v err=%v", done, err)
	}
	if cfg.Port != 4949 || cfg.Threads != 2000 || len(cfg.Sort) != 2 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}
func TestParseRejectsDuplicatePath(t *testing.T) {
	_, _, err := Parse([]string{"-s", "wp:a", "--sort", "wp:b"}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error")
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

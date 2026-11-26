package config

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

func TestParseDefaultsAndStreams(t *testing.T) {
	cfg, done, err := Parse([]string{"--stream", "wp:wp-content", "-s", "shop:cart", "--code", "303,404,303,200"}, &bytes.Buffer{})
	if err != nil || done {
		t.Fatalf("parse: done=%v err=%v", done, err)
	}
	if cfg.WSPort != 4949 || cfg.Threads != 2000 || len(cfg.Streams) != 2 || cfg.Probes != nil {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if cfg.ConnectTimeout != 5*time.Second || cfg.ResponseTimeout != 8*time.Second {
		t.Fatalf("timeouts: connect=%v response=%v", cfg.ConnectTimeout, cfg.ResponseTimeout)
	}
	if len(cfg.SuccessCodes) != 2 || cfg.SuccessCodes[0] != 303 || cfg.SuccessCodes[1] != 404 {
		t.Fatalf("success codes = %v", cfg.SuccessCodes)
	}
}

func TestParseWSPortAndProbes(t *testing.T) {
	for _, args := range [][]string{
		{"-ws-port", "4200", "-p", "http:80,https:443,3000"},
		{"--ws-port", "4200", "--ports", "http:80,https:443,3000"},
	} {
		cfg, _, err := Parse(args, &bytes.Buffer{})
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if cfg.WSPort != 4200 {
			t.Fatalf("%v: ws-port = %d", args, cfg.WSPort)
		}
		if want := "[http:80 https:443 https:3000 http:3000]"; fmt.Sprint(cfg.Probes) != want {
			t.Fatalf("%v: probes = %v, want %s", args, cfg.Probes, want)
		}
	}
}

func TestParseRejectsBadPorts(t *testing.T) {
	for _, args := range [][]string{
		{"--port", "4949"},
		{"--ws-port", "0"},
		{"--ws-port", "65536"},
		{"-p", "4949x"},
		{"-p", "ftp:21"},
		{"-p", "80", "-p", "443"},
	} {
		if _, _, err := Parse(args, &bytes.Buffer{}); err == nil {
			t.Errorf("%v accepted", args)
		}
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

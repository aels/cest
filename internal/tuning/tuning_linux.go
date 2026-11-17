//go:build linux

package tuning

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const desiredNoFile = uint64(524287)

// Apply attempts process and host network tuning. Every setting is independent:
// lack of permission never prevents the application from starting.
func Apply(report func(string)) {
	if report == nil {
		report = func(string) {}
	}
	applyNoFile(report)
	applySysctl(report, "net.ipv4.ip_local_port_range", "/proc/sys/net/ipv4/ip_local_port_range", "1024 65535")
	applySysctl(report, "net.ipv4.tcp_tw_reuse", "/proc/sys/net/ipv4/tcp_tw_reuse", "1")
	applySysctl(report, "net.ipv4.tcp_fin_timeout", "/proc/sys/net/ipv4/tcp_fin_timeout", "2")
}

func applyNoFile(report func(string)) {
	var old unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &old); err != nil {
		report(fmt.Sprintf("[fd] ulimit -n %d (skipped: %v)", desiredNoFile, err))
		return
	}
	if old.Cur == desiredNoFile {
		report(fmt.Sprintf("[fd] ulimit -n %d (ok)", desiredNoFile))
		return
	}

	// Match `ulimit -n`: change the soft limit without lowering an existing
	// hard limit. Raising a too-low hard limit requires CAP_SYS_RESOURCE.
	target := unix.Rlimit{Cur: desiredNoFile, Max: old.Max}
	if old.Max < desiredNoFile {
		target.Max = desiredNoFile
	}
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &target); err != nil {
		if old.Max < desiredNoFile {
			report(fmt.Sprintf("[fd] ulimit -n %d (skipped: hard limit is %d: %v)", desiredNoFile, old.Max, err))
			return
		}
		report(fmt.Sprintf("[fd] ulimit -n %d (skipped: %v)", desiredNoFile, err))
		return
	}
	report(fmt.Sprintf("[fd] ulimit -n %d (ok)", desiredNoFile))
}

func applySysctl(report func(string), name, path, value string) {
	current, err := os.ReadFile(path)
	if err == nil && strings.Join(strings.Fields(string(current)), " ") == value {
		report(fmt.Sprintf("[tcp] %s=%s (ok)", name, value))
		return
	}
	if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
		report(fmt.Sprintf("[tcp] %s=%s (skipped: %v)", name, value, err))
		return
	}
	report(fmt.Sprintf("[tcp] %s=%s (ok)", name, value))
}

//go:build !linux

package tuning

// Apply reports that Linux-specific startup tuning is unavailable.
func Apply(report func(string)) {
	if report != nil {
		report("[tuning] Linux startup tuning (skipped: unsupported operating system)")
	}
}

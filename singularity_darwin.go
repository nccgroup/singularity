package singularity

import "syscall"

// Currently not supported on macOS, this is a blank function to help compilation
func useIPTransparent(_, _ string, _ syscall.RawConn) error {
	return nil
}

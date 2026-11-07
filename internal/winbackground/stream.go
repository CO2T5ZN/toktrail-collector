package winbackground

import "io"

var copyStream = copyCollectorStream

// copyCollectorStream reports stream failures to the supervisor immediately.
// Stopping after a failed log write without stopping the child can leave it
// blocked forever on a full stdout/stderr pipe.
func copyCollectorStream(dst io.Writer, src io.Reader, stop func()) error {
	_, err := io.Copy(dst, src)
	if err != nil && stop != nil {
		stop()
	}
	return err
}

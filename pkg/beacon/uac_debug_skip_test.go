package beacon

import (
	"os"
	"testing"
)

// skipUnlessUACDebug skips interactive UAC/elevation debug tests unless
// DARK_ARTS_UAC_DEBUG=1 is set. These tests trigger UAC prompts, COM
// elevation monikers, and can block for a long time in automated runs.
func skipUnlessUACDebug(t *testing.T) {
	t.Helper()
	if os.Getenv("DARK_ARTS_UAC_DEBUG") == "" {
		t.Skip("interactive UAC debug test; set DARK_ARTS_UAC_DEBUG=1 to run")
	}
}

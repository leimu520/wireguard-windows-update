package tunnel

import "testing"

func TestRandomListenPort(t *testing.T) {
	const current = uint16(51829)
	for i := 0; i < 200; i++ {
		port, err := randomListenPort(current)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if port == current {
			t.Fatalf("iteration %d: returned the port being escaped (%d)", i, current)
		}
		if port < 10240 {
			t.Fatalf("iteration %d: port %d below the reserved floor 10240", i, port)
		}
	}
}

// The quiet window opens after reconnectSilenceAfter attempts and is retried
// only after another full round of them, so that a driver refusing the
// zero-peer write does not turn every attempt into a strip attempt.
func TestSilenceDue(t *testing.T) {
	// Not before the port rotation rung has had its chances: attempts up to
	// reconnectSilenceAfter are ordinary (light, force, force, rotate...).
	for attempts := 1; attempts <= reconnectSilenceAfter; attempts++ {
		if silenceDue(attempts, 0) {
			t.Fatalf("attempt %d: quiet window opened before the rotation rung was exhausted (threshold %d)", attempts, reconnectSilenceAfter)
		}
	}
	if !silenceDue(reconnectSilenceAfter+1, 0) {
		t.Fatalf("attempt %d: quiet window should have opened", reconnectSilenceAfter+1)
	}
	// Right after a window, retries wait another full round.
	if silenceDue(reconnectSilenceAfter+2, reconnectSilenceAfter+1) {
		t.Fatalf("attempt %d: quiet window retried too soon after the last one", reconnectSilenceAfter+2)
	}
	if !silenceDue(reconnectSilenceAfter+1+reconnectSilenceAfter, reconnectSilenceAfter+1) {
		t.Fatalf("attempt %d: quiet window should have opened again", reconnectSilenceAfter+1+reconnectSilenceAfter)
	}
}

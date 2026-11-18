package sync

import (
	"github.com/olelbis/myminivault/internal/model"
	"testing"
	"time"
)

func TestCriticalTombstoneBlocksLegacyResurrection(t *testing.T) {
	now := time.Now()
	for _, updated := range []time.Time{time.Time{}, now.Add(-time.Hour), now} {
		main := &model.ExtendedVault{Data: map[string]string{}}
		MarkKeyDeletedAt(main, "API_KEY", now)
		shared := &model.ExtendedVault{Data: map[string]string{"API_KEY": "fake-deleted-secret"}}
		if !updated.IsZero() {
			MarkKeyUpdatedAt(shared, "API_KEY", updated)
		}
		if ShouldImportSharedValue(main, shared, "API_KEY") {
			t.Fatal("stale or timestamp-free shared value bypasses main tombstone")
		}
		ImportSharedVault(main, shared, now.Add(time.Hour))
		if _, exists := main.Data["API_KEY"]; exists {
			t.Fatal("deleted key resurrected")
		}
	}
}

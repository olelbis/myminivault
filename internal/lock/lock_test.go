package lock

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWithFileCreatesLockWithRestrictivePermissions(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "vault.lock")

	called := false
	if err := WithFile(lockPath, func() error {
		called = true
		return nil
	}); err != nil {
		t.Fatalf("WithFile returned error: %v", err)
	}
	if !called {
		t.Fatal("callback was not called")
	}

	info, err := os.Stat(lockPath)
	if err != nil {
		t.Fatalf("stat lock file: %v", err)
	}
	if got := info.Mode().Perm(); got&0077 != 0 {
		t.Fatalf("lock file mode = %04o, want owner-only permissions", got)
	}
}

func TestWithFileReturnsCallbackError(t *testing.T) {
	want := errors.New("callback failed")
	err := WithFile(filepath.Join(t.TempDir(), "vault.lock"), func() error {
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("WithFile error = %v, want %v", err, want)
	}
}

func TestWithFileTimeoutRunsCallbackWhenLockIsFree(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "vault.lock")

	called := false
	if err := WithFileTimeout(lockPath, time.Second, 10*time.Millisecond, func() error {
		called = true
		return nil
	}); err != nil {
		t.Fatalf("WithFileTimeout returned error: %v", err)
	}
	if !called {
		t.Fatal("callback was not called")
	}
}

func TestWithFileReportsOpenError(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "missing", "vault.lock")
	called := false

	err := WithFile(lockPath, func() error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("expected open error")
	}
	if called {
		t.Fatal("callback should not run when lock file cannot be opened")
	}
}

func TestWithFileSerializesConcurrentCallbacks(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "vault.lock")
	firstStarted := make(chan struct{})
	firstCanFinish := make(chan struct{})
	secondEntered := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if err := WithFile(lockPath, func() error {
			close(firstStarted)
			<-firstCanFinish
			return nil
		}); err != nil {
			t.Errorf("first WithFile returned error: %v", err)
		}
	}()

	<-firstStarted

	go func() {
		defer wg.Done()
		if err := WithFile(lockPath, func() error {
			close(secondEntered)
			return nil
		}); err != nil {
			t.Errorf("second WithFile returned error: %v", err)
		}
	}()

	select {
	case <-secondEntered:
		t.Fatal("second callback entered before first lock was released")
	case <-time.After(100 * time.Millisecond):
	}

	close(firstCanFinish)

	select {
	case <-secondEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("second callback did not enter after first lock was released")
	}

	wg.Wait()
}

func TestWithFileTimeoutReturnsReadableTimeout(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "vault.lock")
	firstStarted := make(chan struct{})
	firstCanFinish := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		if err := WithFile(lockPath, func() error {
			close(firstStarted)
			<-firstCanFinish
			return nil
		}); err != nil {
			t.Errorf("first WithFile returned error: %v", err)
		}
	}()

	<-firstStarted

	called := false
	err := WithFileTimeout(lockPath, 50*time.Millisecond, 10*time.Millisecond, func() error {
		called = true
		return nil
	})
	close(firstCanFinish)
	<-done

	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out waiting for vault lock") {
		t.Fatalf("error = %v, want readable timeout", err)
	}
	if called {
		t.Fatal("callback should not run after lock timeout")
	}
}

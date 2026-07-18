package rollback

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/olelbis/myminivault/internal/model"
	vaultpaths "github.com/olelbis/myminivault/internal/paths"
)

const StateFileName = "rollback-state.json"

type State struct {
	VaultID         string    `json:"vault_id"`
	HighestRevision int64     `json:"highest_revision"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type CheckResult struct {
	Status string
	Detail string
	State  *State
}

func EnsureMetadata(meta *model.VaultMetadata) error {
	if meta.VaultID == "" {
		id, err := randomID()
		if err != nil {
			return err
		}
		meta.VaultID = id
	}
	if meta.Revision < 1 {
		meta.Revision = 1
	}
	return nil
}

func PrepareNextRevision(meta *model.VaultMetadata, state *State) error {
	legacy := meta.VaultID == "" || meta.Revision < 1
	if err := EnsureMetadata(meta); err != nil {
		return err
	}
	if legacy {
		if state != nil && state.VaultID == meta.VaultID && state.HighestRevision >= meta.Revision {
			meta.Revision = state.HighestRevision + 1
		}
		return nil
	}
	next := meta.Revision + 1
	if state != nil && state.VaultID == meta.VaultID && state.HighestRevision >= next {
		next = state.HighestRevision + 1
	}
	meta.Revision = next
	return nil
}

func Check(path string, meta model.VaultMetadata) CheckResult {
	state, err := LoadState(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if meta.VaultID == "" || meta.Revision == 0 {
				return CheckResult{Status: "OK", Detail: "legacy vault; rollback state will be initialized on next save"}
			}
			return CheckResult{Status: "WARN", Detail: fmt.Sprintf("rollback state missing; current vault revision %d", meta.Revision)}
		}
		return CheckResult{Status: "WARN", Detail: "rollback state unreadable: " + err.Error()}
	}
	if meta.VaultID == "" || meta.Revision == 0 {
		return CheckResult{Status: "WARN", Detail: "trusted state exists but vault has legacy revision metadata", State: state}
	}
	if state.VaultID != meta.VaultID {
		return CheckResult{Status: "WARN", Detail: fmt.Sprintf("vault id mismatch; state=%s vault=%s", state.VaultID, meta.VaultID), State: state}
	}
	if meta.Revision < state.HighestRevision {
		return CheckResult{Status: "WARN", Detail: fmt.Sprintf("possible rollback: vault revision %d below trusted %d", meta.Revision, state.HighestRevision), State: state}
	}
	return CheckResult{Status: "OK", Detail: fmt.Sprintf("revision %d, trusted %d", meta.Revision, state.HighestRevision), State: state}
}

func LoadState(path string) (*State, error) {
	if err := vaultpaths.RejectSymlink(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	if state.VaultID == "" {
		return nil, errors.New("missing vault_id")
	}
	if state.HighestRevision < 1 {
		return nil, errors.New("invalid highest_revision")
	}
	return &state, nil
}

func SaveState(path string, meta model.VaultMetadata) error {
	if meta.VaultID == "" || meta.Revision < 1 {
		return errors.New("vault rollback metadata is incomplete")
	}
	state := State{
		VaultID:         meta.VaultID,
		HighestRevision: meta.Revision,
		UpdatedAt:       time.Now().UTC(),
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeAtomic(path, data)
}

func writeAtomic(path string, data []byte) error {
	tempFile := path + ".tmp"
	for _, p := range []string{path, tempFile} {
		if err := vaultpaths.RejectSymlink(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	file, err := vaultpaths.OpenFileCreateExclusiveChecked(tempFile, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(tempFile)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(tempFile)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tempFile)
		return err
	}
	if err := os.Rename(tempFile, path); err != nil {
		_ = os.Remove(tempFile)
		return err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return err
	}
	return vaultpaths.SyncParentDir(path)
}

func randomID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

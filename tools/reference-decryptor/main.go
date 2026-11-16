// reference-decryptor is a small, intentionally standalone MYMV v2 decryptor.
//
// It exists as an executable reading companion to docs/format.md. It avoids
// importing myminivault internal packages so tests can catch drift between the
// documented file format and an independent reader.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
)

const (
	currentVersion    byte = 2
	legacyVersion     byte = 1
	headerSize             = 8
	saltSize               = 16
	nonceSize              = 12
	checksumSize           = sha256.Size
	kindMainVault          = 1
	kindRecoveryVault      = 2
	kindSharedToken        = 3
)

var magic = []byte{'M', 'Y', 'M', 'V'}

type metadata struct {
	Algorithm        string `json:"algorithm"`
	KDF              string `json:"kdf"`
	ScryptN          int    `json:"scrypt_n"`
	ScryptR          int    `json:"scrypt_r"`
	ScryptP          int    `json:"scrypt_p"`
	Argon2MemoryKiB  uint32 `json:"argon2_memory_kib"`
	Argon2Time       uint32 `json:"argon2_time"`
	Argon2Threads    uint8  `json:"argon2_threads"`
	KeySize          int    `json:"key_size"`
	SaltSize         int    `json:"salt_size"`
	NonceSize        int    `json:"nonce_size"`
	Payload          string `json:"payload"`
	CiphertextLayout string `json:"ciphertext_layout"`
}

type parsedContainer struct {
	Kind       byte
	Salt       []byte
	Ciphertext []byte
	AAD        []byte
	Metadata   metadata
}

func main() {
	var passwordFile string
	var recoveryKeyFile string
	var tokenKeyFile string
	var legacyScryptN, legacyScryptR, legacyScryptP int
	flag.StringVar(&passwordFile, "password-file", "", "file containing the master password, without requiring it in process arguments")
	flag.StringVar(&recoveryKeyFile, "recovery-key-file", "", "file containing a recovery key for a recovery vault")
	flag.StringVar(&tokenKeyFile, "token-key-file", "", "file containing a raw 32-byte token master key for a shared-token vault")
	flag.IntVar(&legacyScryptN, "legacy-scrypt-n", 0, "scrypt N for a MYMV v1 main vault (requires R and P)")
	flag.IntVar(&legacyScryptR, "legacy-scrypt-r", 0, "scrypt R for a MYMV v1 main vault (requires N and P)")
	flag.IntVar(&legacyScryptP, "legacy-scrypt-p", 0, "scrypt P for a MYMV v1 main vault (requires N and R)")
	flag.Parse()

	provided := 0
	for _, path := range []string{passwordFile, recoveryKeyFile, tokenKeyFile} {
		if path != "" {
			provided++
		}
	}
	if flag.NArg() != 1 || provided != 1 {
		fmt.Fprintln(os.Stderr, "usage: reference-decryptor (--password-file <file> | --recovery-key-file <file> | --token-key-file <file>) <vault-file>")
		os.Exit(2)
	}
	legacyRequested := legacyScryptN != 0 || legacyScryptR != 0 || legacyScryptP != 0
	if legacyRequested && (passwordFile == "" || legacyScryptN < 2 || legacyScryptR < 1 || legacyScryptP < 1) {
		fmt.Fprintln(os.Stderr, "MYMV v1 requires --password-file and positive --legacy-scrypt-n, --legacy-scrypt-r, and --legacy-scrypt-p")
		os.Exit(2)
	}
	kind := byte(kindMainVault)
	keyFile := passwordFile
	if recoveryKeyFile != "" {
		kind = kindRecoveryVault
		keyFile = recoveryKeyFile
	} else if tokenKeyFile != "" {
		kind = kindSharedToken
		keyFile = tokenKeyFile
	}

	keyMaterial, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read key file: %v\n", err)
		os.Exit(1)
	}
	if kind != kindSharedToken {
		keyMaterial = bytes.TrimRight(keyMaterial, "\r\n")
	}
	defer wipe(keyMaterial)

	var plaintext []byte
	if kind == kindRecoveryVault {
		plaintext, err = decryptRecoveryFile(flag.Arg(0), keyMaterial)
	} else if kind == kindSharedToken {
		plaintext, err = decryptSharedTokenFile(flag.Arg(0), keyMaterial)
	} else if legacyRequested {
		plaintext, err = decryptV1MainFile(flag.Arg(0), keyMaterial, legacyScryptN, legacyScryptR, legacyScryptP)
	} else {
		plaintext, err = decryptFile(flag.Arg(0), keyMaterial)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "decrypt: %v\n", err)
		os.Exit(1)
	}

	if _, err := os.Stdout.Write(plaintext); err != nil {
		fmt.Fprintf(os.Stderr, "write plaintext: %v\n", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write([]byte("\n")); err != nil {
		fmt.Fprintf(os.Stderr, "write newline: %v\n", err)
		os.Exit(1)
	}
}

func decryptFile(path string, masterPassword []byte) ([]byte, error) {
	return decryptFileKind(path, masterPassword, kindMainVault)
}

func decryptV1MainFile(path string, masterPassword []byte, n, r, p int) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < headerSize+saltSize+nonceSize {
		return nil, errors.New("MYMV v1 container too short")
	}
	if !bytes.Equal(data[:len(magic)], magic) || data[4] != legacyVersion || data[5] != kindMainVault || data[6] != 0 || data[7] != 0 {
		return nil, errors.New("expected MYMV v1 main vault header")
	}
	key, err := scrypt.Key(masterPassword, data[headerSize:headerSize+saltSize], n, r, p, 32)
	if err != nil {
		return nil, err
	}
	defer wipe(key)
	// MYMV v1 has no authenticated header; AES-GCM authenticates only its payload.
	payload, err := decryptPayload(data[headerSize+saltSize:], key, nil)
	if err != nil {
		return nil, err
	}
	return stripChecksum(payload)
}

func decryptRecoveryFile(path string, recoveryKey []byte) ([]byte, error) {
	plaintext, err := decryptFileKind(path, recoveryKey, kindRecoveryVault)
	if err != nil {
		return nil, err
	}
	var vault struct {
		Recovery *struct {
			KeyHash []byte `json:"recovery_key_hash"`
		} `json:"recovery"`
	}
	if err := json.Unmarshal(plaintext, &vault); err != nil {
		return nil, fmt.Errorf("invalid recovery payload: %w", err)
	}
	// Recovery keys contain 32 random bytes; this must match the stored verifier.
	hash := sha256.Sum256(recoveryKey)
	if vault.Recovery == nil || subtle.ConstantTimeCompare(vault.Recovery.KeyHash, hash[:]) != 1 {
		return nil, errors.New("recovery key verifier mismatch")
	}
	return plaintext, nil
}

func decryptSharedTokenFile(path string, tokenMasterKey []byte) ([]byte, error) {
	if len(tokenMasterKey) != 32 {
		return nil, errors.New("token master key must be exactly 32 bytes")
	}
	return decryptFileKind(path, tokenMasterKey, kindSharedToken)
}

func decryptFileKind(path string, keyMaterial []byte, kind byte) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	parsed, err := parseMYMV2(data)
	if err != nil {
		return nil, err
	}
	if parsed.Kind != kind {
		return nil, fmt.Errorf("unsupported container kind %d: expected %d", parsed.Kind, kind)
	}

	if err := validateKDFForKind(parsed.Metadata, kind); err != nil {
		return nil, err
	}
	key, err := deriveKey(keyMaterial, parsed.Salt, parsed.Metadata, kind)
	if err != nil {
		return nil, err
	}
	defer wipe(key)

	payload, err := decryptPayload(parsed.Ciphertext, key, parsed.AAD)
	if err != nil {
		return nil, err
	}

	return stripChecksum(payload)
}

func parseMYMV2(data []byte) (parsedContainer, error) {
	if len(data) < headerSize+saltSize {
		return parsedContainer{}, errors.New("container too short")
	}
	if !bytes.Equal(data[:len(magic)], magic) {
		return parsedContainer{}, errors.New("missing MYMV magic")
	}
	if data[4] != currentVersion {
		return parsedContainer{}, fmt.Errorf("unsupported MYMV version %d", data[4])
	}

	metaLen := int(binary.BigEndian.Uint16(data[6:8]))
	payloadOffset := headerSize + metaLen
	if len(data) < payloadOffset+saltSize {
		return parsedContainer{}, errors.New("container metadata or salt truncated")
	}

	var meta metadata
	if err := json.Unmarshal(data[headerSize:payloadOffset], &meta); err != nil {
		return parsedContainer{}, fmt.Errorf("invalid metadata JSON: %w", err)
	}
	if err := validateMetadata(meta); err != nil {
		return parsedContainer{}, err
	}

	aadEnd := payloadOffset + saltSize
	return parsedContainer{
		Kind:       data[5],
		Salt:       append([]byte(nil), data[payloadOffset:aadEnd]...),
		Ciphertext: append([]byte(nil), data[aadEnd:]...),
		AAD:        append([]byte(nil), data[:aadEnd]...),
		Metadata:   meta,
	}, nil
}

func validateMetadata(meta metadata) error {
	if meta.Algorithm != "AES-256-GCM" {
		return fmt.Errorf("unsupported algorithm %q", meta.Algorithm)
	}
	if meta.KDF != "argon2id" && meta.KDF != "scrypt" && meta.KDF != "hkdf-sha256" {
		return fmt.Errorf("unsupported KDF %q", meta.KDF)
	}
	if meta.Payload != "sha256-prefix-json" {
		return fmt.Errorf("unsupported payload %q", meta.Payload)
	}
	if meta.CiphertextLayout != "nonce-prefixed" {
		return fmt.Errorf("unsupported ciphertext layout %q", meta.CiphertextLayout)
	}
	if meta.SaltSize != saltSize {
		return fmt.Errorf("unsupported salt size %d", meta.SaltSize)
	}
	if meta.NonceSize != nonceSize {
		return fmt.Errorf("unsupported nonce size %d", meta.NonceSize)
	}
	if meta.KeySize != 32 {
		return fmt.Errorf("unsupported key size %d", meta.KeySize)
	}
	switch meta.KDF {
	case "argon2id":
		if meta.Argon2MemoryKiB < 19*1024 || meta.Argon2MemoryKiB > 256*1024 {
			return errors.New("invalid argon2id memory metadata")
		}
		if meta.Argon2Time < 1 || meta.Argon2Time > 8 {
			return errors.New("invalid argon2id time metadata")
		}
		if meta.Argon2Threads < 1 || meta.Argon2Threads > 8 {
			return errors.New("invalid argon2id threads metadata")
		}
	case "scrypt":
		if meta.ScryptN < 2 || meta.ScryptR < 1 || meta.ScryptP < 1 {
			return errors.New("invalid scrypt metadata")
		}
	}
	return nil
}

func validateKDFForKind(meta metadata, kind byte) error {
	if kind == kindMainVault && meta.KDF == "hkdf-sha256" {
		return errors.New("HKDF is not supported for main vaults")
	}
	if (kind == kindRecoveryVault || kind == kindSharedToken) && meta.KDF != "hkdf-sha256" {
		return errors.New("reference tool supports only HKDF recovery and shared-token vaults")
	}
	return nil
}

func deriveKey(keyMaterial, salt []byte, meta metadata, kind byte) ([]byte, error) {
	if meta.KDF == "argon2id" {
		return argon2.IDKey(keyMaterial, salt, meta.Argon2Time, meta.Argon2MemoryKiB, meta.Argon2Threads, uint32(meta.KeySize)), nil // #nosec G115 -- validateMetadata requires the only supported key size, 32.
	}
	if meta.KDF == "hkdf-sha256" {
		info := "myminivault:recovery-vault"
		if kind == kindSharedToken {
			info = "myminivault:shared-token-vault"
		}
		key := make([]byte, meta.KeySize)
		if _, err := io.ReadFull(hkdf.New(sha256.New, keyMaterial, salt, []byte(info)), key); err != nil {
			return nil, err
		}
		return key, nil
	}
	return scrypt.Key(keyMaterial, salt, meta.ScryptN, meta.ScryptR, meta.ScryptP, meta.KeySize)
}

func decryptPayload(ciphertext, key, aad []byte) ([]byte, error) {
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], aad)
}

func stripChecksum(payload []byte) ([]byte, error) {
	if len(payload) <= checksumSize {
		return nil, errors.New("payload too short")
	}

	expected := payload[:checksumSize]
	plaintext := payload[checksumSize:]
	actual := sha256.Sum256(plaintext)
	if !bytes.Equal(expected, actual[:]) {
		return nil, errors.New("checksum failed")
	}
	return plaintext, nil
}

func wipe(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

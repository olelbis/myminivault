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
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

const (
	currentVersion byte = 2
	headerSize          = 8
	saltSize            = 16
	nonceSize           = 12
	checksumSize        = sha256.Size
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
	flag.StringVar(&passwordFile, "password-file", "", "file containing the master password, without requiring it in process arguments")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: reference-decryptor --password-file <file> <vault.db>")
		os.Exit(2)
	}
	if passwordFile == "" {
		fmt.Fprintln(os.Stderr, "missing --password-file")
		os.Exit(2)
	}

	password, err := os.ReadFile(passwordFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read password file: %v\n", err)
		os.Exit(1)
	}
	password = bytes.TrimRight(password, "\r\n")
	defer wipe(password)

	plaintext, err := decryptFile(flag.Arg(0), password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decrypt: %v\n", err)
		os.Exit(1)
	}

	os.Stdout.Write(plaintext)
	os.Stdout.Write([]byte("\n"))
}

func decryptFile(path string, password []byte) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	parsed, err := parseMYMV2(data)
	if err != nil {
		return nil, err
	}
	if parsed.Kind != 1 {
		return nil, fmt.Errorf("unsupported container kind %d: reference tool expects main vault", parsed.Kind)
	}

	key, err := deriveKey(password, parsed.Salt, parsed.Metadata)
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
	if meta.KDF != "argon2id" && meta.KDF != "scrypt" {
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

func deriveKey(password, salt []byte, meta metadata) ([]byte, error) {
	if meta.KDF == "argon2id" {
		return argon2.IDKey(password, salt, meta.Argon2Time, meta.Argon2MemoryKiB, meta.Argon2Threads, uint32(meta.KeySize)), nil
	}
	return scrypt.Key(password, salt, meta.ScryptN, meta.ScryptR, meta.ScryptP, meta.KeySize)
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

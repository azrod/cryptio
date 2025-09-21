package cryptio

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

// SecurityLevel defines the strength of key derivation for encryption.
type SecurityLevel int

const (
	SecurityUltraFast SecurityLevel = iota // Test/devices only (not for production)
	SecurityStandard                       // OWASP recommended (default)
	SecurityMedium                         // NIST/Enterprise
	SecurityHigh                           // Critical, health, finance
	SecurityExtreme                        // Ultra-secure, vaults, secrets
)

func (sl SecurityLevel) String() string {
	switch sl {
	case SecurityUltraFast:
		return "UltraFast"
	case SecurityStandard:
		return "Standard"
	case SecurityMedium:
		return "Medium"
	case SecurityHigh:
		return "High"
	case SecurityExtreme:
		return "Extreme"
	default:
		return "Unknown"
	}
}

// Argon2Profile defines a memory/CPU tradeoff profile as per Argon2id recommendations.
type Argon2Profile int

const (
	ProfileRAMHeavy Argon2Profile = iota // m=47104 (46 MiB), t=1, p=1
	ProfileBalanced                      // m=19456 (19 MiB), t=2, p=1
	ProfileTradeoff                      // m=12288 (12 MiB), t=3, p=1
	ProfileCPUFavor                      // m=9216  (9 MiB), t=4, p=1
	ProfileCPUHeavy                      // m=7168  (7 MiB), t=5, p=1
)

func (pf Argon2Profile) String() string {
	switch pf {
	case ProfileRAMHeavy:
		return "RAMHeavy"
	case ProfileBalanced:
		return "Balanced"
	case ProfileTradeoff:
		return "Tradeoff"
	case ProfileCPUFavor:
		return "CPUFavor"
	case ProfileCPUHeavy:
		return "CPUHeavy"
	default:
		return "Unknown"
	}
}

// securityParams holds the Argon2id configuration for encryption.
type securityParams struct {
	SaltSize     int
	KeySize      uint32
	NonceSize    int
	ArgonTime    uint32
	ArgonMem     uint32
	ArgonThreads uint8
}

// --- Base param tables ---

var argon2Profiles = map[Argon2Profile]securityParams{
	ProfileRAMHeavy: {
		SaltSize:     16,
		KeySize:      32,
		NonceSize:    12,
		ArgonTime:    1,
		ArgonMem:     47104, // 46 MiB
		ArgonThreads: 1,
	},
	ProfileBalanced: {
		SaltSize:     16,
		KeySize:      32,
		NonceSize:    12,
		ArgonTime:    2,
		ArgonMem:     19456, // 19 MiB
		ArgonThreads: 1,
	},
	ProfileTradeoff: {
		SaltSize:     16,
		KeySize:      32,
		NonceSize:    12,
		ArgonTime:    3,
		ArgonMem:     12288, // 12 MiB
		ArgonThreads: 1,
	},
	ProfileCPUFavor: {
		SaltSize:     16,
		KeySize:      32,
		NonceSize:    12,
		ArgonTime:    4,
		ArgonMem:     9216, // 9 MiB
		ArgonThreads: 1,
	},
	ProfileCPUHeavy: {
		SaltSize:     16,
		KeySize:      32,
		NonceSize:    12,
		ArgonTime:    5,
		ArgonMem:     7168, // 7 MiB
		ArgonThreads: 1,
	},
}

var securityLevels = map[SecurityLevel]securityParams{
	SecurityUltraFast: {
		SaltSize:     16,
		KeySize:      32,
		NonceSize:    12,
		ArgonTime:    1,
		ArgonMem:     16 * 1024, // 16 MiB
		ArgonThreads: 1,
	},
	SecurityStandard: {
		SaltSize:     16,
		KeySize:      32,
		NonceSize:    12,
		ArgonTime:    2,
		ArgonMem:     64 * 1024, // 64 MiB (OWASP)
		ArgonThreads: 1,
	},
	SecurityMedium: {
		SaltSize:     24,
		KeySize:      32,
		NonceSize:    12,
		ArgonTime:    3,
		ArgonMem:     128 * 1024, // 128 MiB (NIST moderate)
		ArgonThreads: 2,
	},
	SecurityHigh: {
		SaltSize:     32,
		KeySize:      32,
		NonceSize:    12,
		ArgonTime:    4,
		ArgonMem:     256 * 1024, // 256 MiB (PHC/Argon2 paper)
		ArgonThreads: 2,
	},
	SecurityExtreme: {
		SaltSize:     32,
		KeySize:      32,
		NonceSize:    12,
		ArgonTime:    6,
		ArgonMem:     1024 * 1024, // 1 GiB (ultra secure)
		ArgonThreads: 4,
	},
}

// --- Combination logic ---

// max is a generic function that returns the maximum of two comparable numbers.
func max[T ~int | ~uint8 | ~uint32](a, b T) T {
	if a > b {
		return a
	}
	return b
}

// mergeParams combines a profile and a security level to produce the most "refined" Argon2id config.
// Both profile and security level are required.
func mergeParams(level SecurityLevel, profile Argon2Profile) (securityParams, error) {
	base := securityParams{}
	p, okp := argon2Profiles[profile]
	l, okl := securityLevels[level]

	if !okp {
		return base, errors.New("unknown Argon2 profile")
	}
	if !okl {
		return base, errors.New("unknown security level")
	}

	// Combine: choose the maximum value for each security-relevant field
	base.ArgonTime = max(p.ArgonTime, l.ArgonTime)
	base.ArgonMem = max(p.ArgonMem, l.ArgonMem)
	base.ArgonThreads = max(p.ArgonThreads, l.ArgonThreads)
	base.SaltSize = max(p.SaltSize, l.SaltSize)
	base.KeySize = max(p.KeySize, l.KeySize)
	base.NonceSize = max(p.NonceSize, l.NonceSize)
	return base, nil
}

// --- Main API ---

// Client contains the passphrase and security parameters.
type Client struct {
	passphrase []byte
	params     securityParams
}

// New creates a new client using both a SecurityLevel and an Argon2Profile.
// Both arguments are required.
func New(passphrase string, level SecurityLevel, profile Argon2Profile) (*Client, error) {
	params, err := mergeParams(level, profile)
	if err != nil {
		return nil, err
	}
	return &Client{
		passphrase: []byte(passphrase),
		params:     params,
	}, nil
}

// deriveKey generates a key using Argon2id from the passphrase and salt.
func (c *Client) deriveKey(salt []byte) []byte {
	return argon2.IDKey(c.passphrase, salt, c.params.ArgonTime, c.params.ArgonMem, c.params.ArgonThreads, c.params.KeySize)
}

// EncryptRaw encrypts a byte slice and returns the encrypted byte slice (salt+nonce+ciphertext).
func (c *Client) EncryptRaw(plaintext []byte) ([]byte, error) {
	salt := make([]byte, c.params.SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key := c.deriveKey(salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, c.params.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	finalData := append(append(salt, nonce...), ciphertext...)
	return finalData, nil
}

// DecryptRaw decrypts an encrypted byte slice (salt+nonce+ciphertext).
func (c *Client) DecryptRaw(encryptedData []byte) ([]byte, error) {
	minLen := c.params.SaltSize + c.params.NonceSize
	if len(encryptedData) < minLen {
		return nil, errors.New("invalid encrypted data")
	}
	salt := encryptedData[:c.params.SaltSize]
	nonce := encryptedData[c.params.SaltSize : c.params.SaltSize+c.params.NonceSize]
	ciphertext := encryptedData[c.params.SaltSize+c.params.NonceSize:]
	key := c.deriveKey(salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// Encrypt encrypts a string and returns a base64-encoded result.
func (c *Client) Encrypt(plaintext string) (string, error) {
	raw, err := c.EncryptRaw([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// Decrypt decrypts a base64-encoded string and returns the plaintext.
func (c *Client) Decrypt(encryptedText string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}
	plaintext, err := c.DecryptRaw(raw)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

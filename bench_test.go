package cryptio

import (
	"testing"
)

// All security levels
var allSecurityLevels = []SecurityLevel{
	SecurityUltraFast,
	SecurityStandard,
	SecurityMedium,
	SecurityHigh,
	SecurityExtreme,
}

// All profiles
var allProfiles = []Argon2Profile{
	ProfileRAMHeavy,
	ProfileBalanced,
	ProfileTradeoff,
	ProfileCPUFavor,
	ProfileCPUHeavy,
}

// Human-friendly name for a combination
func benchName(level SecurityLevel, profile Argon2Profile) string {
	return level.String() + "+" + profile.String()
}

func runBenchCombo(b *testing.B, security SecurityLevel, profile Argon2Profile, plaintext []byte) {
	b.Helper()
	client, err := New("BenchSecret", security, profile)
	if err != nil {
		b.Fatalf("Failed to create client: %v", err)
	}
	var ciphertext []byte
	// Encrypt benchmark
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ciphertext, err = client.EncryptRaw(plaintext)
		if err != nil {
			b.Fatalf("EncryptRaw failed: %v", err)
		}
	}
	b.StopTimer()
	// Decrypt benchmark (not counted in encrypt timing)
	for i := 0; i < 2; i++ {
		plain2, err := client.DecryptRaw(ciphertext)
		if err != nil {
			b.Fatalf("DecryptRaw failed: %v", err)
		}
		if string(plain2) != string(plaintext) {
			b.Fatalf("Decrypted text mismatch: got %s, want %s", string(plain2), string(plaintext))
		}
	}
}

func BenchmarkEncryptDecrypt_AllCombinations(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping exhaustive benchmark in short mode")
	}
	plaintext := []byte("this is a secret message for benchmark")

	for _, security := range allSecurityLevels {
		for _, profile := range allProfiles {
			sec := security
			prof := profile
			name := benchName(sec, prof)
			b.Run(name, func(b *testing.B) {
				runBenchCombo(b, sec, prof, plaintext)
			})
		}
	}
}

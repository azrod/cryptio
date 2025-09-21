package cryptio

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	pass := "SuperSecurePassphrase!"
	security := SecurityStandard
	profile := ProfileBalanced

	client, err := New(pass, security, profile)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	plaintext := "Hello, cryptio world!"
	ciphertext, err := client.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := client.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Expected decrypted to be %q, got %q", plaintext, decrypted)
	}
}

func TestEncryptDecryptRaw(t *testing.T) {
	pass := "RawDataSecret"
	security := SecurityHigh
	profile := ProfileRAMHeavy

	client, err := New(pass, security, profile)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	plaintext := []byte{0x01, 0x02, 0x03, 0xFA, 0xFF}
	ciphertext, err := client.EncryptRaw(plaintext)
	if err != nil {
		t.Fatalf("EncryptRaw failed: %v", err)
	}

	plain2, err := client.DecryptRaw(ciphertext)
	if err != nil {
		t.Fatalf("DecryptRaw failed: %v", err)
	}

	if !bytes.Equal(plaintext, plain2) {
		t.Errorf("Expected decrypted bytes %v, got %v", plaintext, plain2)
	}
}

func TestDifferentPasswordsFail(t *testing.T) {
	security := SecurityMedium
	profile := ProfileCPUFavor

	client1, err := New("PasswordA", security, profile)
	if err != nil {
		t.Fatalf("Failed to create client1: %v", err)
	}
	client2, err := New("PasswordB", security, profile)
	if err != nil {
		t.Fatalf("Failed to create client2: %v", err)
	}
	plaintext := "Sensitive data"
	ciphertext, err := client1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	_, err = client2.Decrypt(ciphertext)
	if err == nil {
		t.Error("Decryption should fail with different password, but did not")
	}
}

func TestDifferentParamsFail(t *testing.T) {
	pass := "SamePassword"
	client1, err := New(pass, SecurityStandard, ProfileTradeoff)
	if err != nil {
		t.Fatalf("Failed to create client1: %v", err)
	}
	client2, err := New(pass, SecurityHigh, ProfileRAMHeavy)
	if err != nil {
		t.Fatalf("Failed to create client2: %v", err)
	}
	plaintext := "Mismatch parameters!"
	ciphertext, err := client1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	_, err = client2.Decrypt(ciphertext)
	if err == nil {
		t.Error("Decryption should fail with different params, but did not")
	}
}

func TestBase64InputOutput(t *testing.T) {
	pass := "Base64Test"
	security := SecurityUltraFast
	profile := ProfileCPUHeavy

	client, err := New(pass, security, profile)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	plaintext := "base64 string?"
	ciphertext, err := client.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// ciphertext should be valid base64
	_, err = base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		t.Errorf("Ciphertext is not valid base64: %v", err)
	}
}

<img align="left" width="250"  src="logo-cryptio.png" alt="Cryptio Logo" />

[![Go Reference](https://img.shields.io/badge/Go-Reference-%2300ADD8.svg?&logo=go&logoColor=white&style=for-the-badge)](https://pkg.go.dev/github.com/azrod/cryptio)
[![Go Report Card](https://goreportcard.com/badge/github.com/azrod/cryptio?style=for-the-badge)](https://goreportcard.com/report/github.com/azrod/cryptio)
[![License: MIT](https://img.shields.io/github/license/azrod/cryptio?style=for-the-badge)](LICENSE)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/azrod/cryptio?style=for-the-badge)

**cryptio** is a Go library for symmetric encryption with Argon2id key derivation, offering multiple security levels and resource usage profiles suitable for a wide range of use cases.

**Minimal & trusted dependencies:**  
cryptio relies only on official Go cryptography libraries ([golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto)) for robust, up-to-date security. No third-party or non-standard dependencies.

<br/>
<br/>

## 🔑 Security Levels & Profiles

### Security Levels

A **SecurityLevel** defines the cryptographic strength of key derivation—how slow and memory-intensive the key derivation should be to resist brute-force or hardware attacks.  
Higher levels mean more security, but also more CPU/RAM usage and slower operations.

- **UltraFast**: For testing/devices only, almost no protection against brute-force.
- **Standard**: Strong and fast, recommended for most apps (follows OWASP guidance).
- **Medium**: Enterprise-grade, NIST-compliant for regulated environments.
- **High**: For highly sensitive data, critical production, health/finance.
- **Extreme**: Vaults and ultra-secure secrets, very slow and memory-hungry.

### Argon2 Profiles

The **Argon2Profile** controls the trade-off between CPU and RAM usage in Argon2id key derivation.

- **RAMHeavy**: Uses a lot of RAM for best GPU/ASIC resistance, fast if enough memory.
- **Balanced**: Good compromise between RAM and CPU.
- **Tradeoff**: Lower RAM, higher CPU.
- **CPUFavor**: Minimal RAM, high CPU.
- **CPUHeavy**: Minimum RAM, maximum CPU (useful for RAM-constrained environments).

**How it works:**  
When you create a cryptio client, you specify both a SecurityLevel and an Argon2Profile.  
The library combines both to set Argon2id parameters (iterations, memory size, parallelism, salt/key/nonce sizes) to maximize security in line with your needs and hardware limits.

---

## 🛡️ Security Levels Table

| Level        | Encrypt/Decrypt Time | Memory Usage | Recommended Usage                    | Reference |
|--------------|---------------------|--------------|--------------------------------------|-----------|
| UltraFast    | ~30–48 ms           | ~7–46 MB     | Test/devices only, **never production** | [OWASP-min](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) |
| Standard     | ~81–209 ms          | ~64 MB       | Standard apps, default               | [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id) |
| Medium       | ~140–233 ms         | ~128 MB      | Enterprise, compliance, multi-user   | [NIST](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| High         | ~388–485 ms         | ~256 MB      | Sensitive/critical data, dedicated servers | [Argon2](https://password-hashing.net/argon2-specs.pdf) |
| Extreme      | >1.2 s              | ~1 GB        | Ultra-secure, vaults, critical secrets | [Argon2](https://password-hashing.net/argon2-specs.pdf) |

> **Benchmarks were run on Apple M1 Pro ARM64**  
> Performance may vary depending on your hardware.

<details>
<summary>Full benchmarks results</summary>

```plain
goos: darwin
goarch: arm64
pkg: github.com/azrod/cryptio
cpu: Apple M1 Pro
BenchmarkEncryptDecrypt_AllCombinations/UltraFast+RAMHeavy-10                 37          30166314 ns/op        48240476 B/op         31 allocs/op
BenchmarkEncryptDecrypt_AllCombinations/UltraFast+Balanced-10                 49          23723713 ns/op        19929020 B/op         39 allocs/op
BenchmarkEncryptDecrypt_AllCombinations/UltraFast+Tradeoff-10                 39          29310855 ns/op        16783549 B/op         47 allocs/op
BenchmarkEncryptDecrypt_AllCombinations/UltraFast+CPUFavor-10                 28          42729129 ns/op        16783817 B/op         55 allocs/op
BenchmarkEncryptDecrypt_AllCombinations/UltraFast+CPUHeavy-10                 24          47863599 ns/op        16784072 B/op         63 allocs/op
BenchmarkEncryptDecrypt_AllCombinations/Standard+RAMHeavy-10                  13          82086885 ns/op        67114944 B/op         39 allocs/op
BenchmarkEncryptDecrypt_AllCombinations/Standard+Balanced-10                  13          81937055 ns/op        67114937 B/op         39 allocs/op
BenchmarkEncryptDecrypt_AllCombinations/Standard+Tradeoff-10                   8         129755547 ns/op        67115194 B/op         47 allocs/op
BenchmarkEncryptDecrypt_AllCombinations/Standard+CPUFavor-10                   6         176435486 ns/op        67115453 B/op         55 allocs/op
BenchmarkEncryptDecrypt_AllCombinations/Standard+CPUHeavy-10                   5         208910383 ns/op        67115707 B/op         63 allocs/op
BenchmarkEncryptDecrypt_AllCombinations/Medium+RAMHeavy-10                     7         144040554 ns/op        134226194 B/op        64 allocs/op
BenchmarkEncryptDecrypt_AllCombinations/Medium+Balanced-10                     7         142956435 ns/op        134227268 B/op        66 allocs/op
BenchmarkEncryptDecrypt_AllCombinations/Medium+Tradeoff-10                     8         140065354 ns/op        134225982 B/op        64 allocs/op
BenchmarkEncryptDecrypt_AllCombinations/Medium+CPUFavor-10                     6         190983125 ns/op        134226706 B/op        76 allocs/op
BenchmarkEncryptDecrypt_AllCombinations/Medium+CPUHeavy-10                     5         233302508 ns/op        134226956 B/op        88 allocs/op
BenchmarkEncryptDecrypt_AllCombinations/High+RAMHeavy-10                       3         391281319 ns/op        268445229 B/op        79 allocs/op
BenchmarkEncryptDecrypt_AllCombinations/High+Balanced-10                       3         390867125 ns/op        268445602 B/op        77 allocs/op
BenchmarkEncryptDecrypt_AllCombinations/High+Tradeoff-10                       3         388630111 ns/op        268443885 B/op        76 allocs/op
BenchmarkEncryptDecrypt_AllCombinations/High+CPUFavor-10                       3         388122486 ns/op        268443917 B/op        76 allocs/op
BenchmarkEncryptDecrypt_AllCombinations/High+CPUHeavy-10                       3         484810695 ns/op        268444269 B/op        87 allocs/op
BenchmarkEncryptDecrypt_AllCombinations/Extreme+RAMHeavy-10                    1        1316354208 ns/op        1073755256 B/op      156 allocs/op
BenchmarkEncryptDecrypt_AllCombinations/Extreme+Balanced-10                    1        1267185542 ns/op        1073755160 B/op      155 allocs/op
BenchmarkEncryptDecrypt_AllCombinations/Extreme+Tradeoff-10                    1        1349435166 ns/op        1073755256 B/op      156 allocs/op
BenchmarkEncryptDecrypt_AllCombinations/Extreme+CPUFavor-10                    1        1265666000 ns/op        1073755608 B/op      156 allocs/op
BenchmarkEncryptDecrypt_AllCombinations/Extreme+CPUHeavy-10                    1        1263802834 ns/op        1073755256 B/op      156 allocs/op
```

</details>

### ℹ️ Why doesn't RAM usage change by profile from Standard upwards?

Starting from the **Standard** security level and above, the memory (RAM) usage remains constant for all Argon2 profiles (RAMHeavy, Balanced, Tradeoff, CPUFavor, CPUHeavy).  
This is because each security level enforces a **minimum memory requirement** recommended by security standards (such as OWASP and NIST).  
Even if you select a profile that would normally use less RAM (e.g., CPUHeavy), the library will **never allocate less memory than the minimum set by the security level**.

- The **profile** can only increase memory usage above this minimum, not decrease it.
- Below the Standard level (e.g., UltraFast), profiles have more impact and memory can vary.
- This behavior ensures that security cannot be weakened by choosing a lower-resource profile at a high security level.

**In summary:**  
> From Standard and up, memory usage is fixed by security policy. Profiles only affect CPU usage (speed), not RAM, at these levels. This guarantees you never accidentally use weaker protection than the chosen level intends.

---

## ✅ How to choose the right security level?

- **UltraFast**  
  - Usage: Testing, prototyping, very limited IoT/mobile devices  
  - _Not for production!_ (low brute-force resistance)
- **Standard**  
  - Usage: Web applications, APIs, microservices, general use  
  - _Recommended default_ (strong security/performance balance)
- **Medium**  
  - Usage: Enterprise, regulated environments (GDPR, NIST), multi-user  
  - _Reinforced security with moderate performance impact_
- **High**  
  - Usage: Highly sensitive data, health, finance, dedicated servers  
  - _High security, requires significant resources_
- **Extreme**  
  - Usage: Vaults, enterprise secrets, critical infrastructure  
  - _Maximum security, very slow, very high memory usage_

**Tip:** Choose the lowest level compatible with your security policy and server workload.  
For 99% of use cases, `Standard` or `Medium` are sufficient.

---

## 🔧 Usage

```go
import "github.com/azrod/cryptio"

func main() {
    // Choose the security level and profile that fit your needs
    client, err := cryptio.New("YourSuperSecurePassphrase", cryptio.SecurityStandard, cryptio.ProfileBalanced)
    if err != nil {
        panic(err)
    }

    // Encrypt a string
    encrypted, err := client.Encrypt("Secret message")
    if err != nil {
        panic(err)
    }

    // Decrypt a string
    decrypted, err := client.Decrypt(encrypted)
    if err != nil {
        panic(err)
    }

    // Encrypt binary data
    encryptedRaw, err := client.EncryptRaw([]byte{0x01, 0x02, 0x03})
    if err != nil {
        panic(err)
    }

    // Decrypt binary data
    decryptedRaw, err := client.DecryptRaw(encryptedRaw)
    if err != nil {
        panic(err)
    }
}
```

---

## 🔬 Security levels and profiles in code

```go
type SecurityLevel int

const (
    SecurityUltraFast SecurityLevel = iota // Test, low-end devices, never production
    SecurityStandard                       // OWASP recommended (default)
    SecurityMedium                         // NIST, enterprise
    SecurityHigh                           // Critical, health, finance
    SecurityExtreme                        // Vault, ultra-high security
)

type Argon2Profile int

const (
    ProfileRAMHeavy Argon2Profile = iota   // Max RAM, fast
    ProfileBalanced                        // Balanced
    ProfileTradeoff                        // Lower RAM, more CPU
    ProfileCPUFavor                        // Favor CPU over RAM
    ProfileCPUHeavy                        // Min RAM, max CPU
)
```

---

## 🔗 References

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id)
- [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Argon2 Password Hashing Competition Spec](https://password-hashing.net/argon2-specs.pdf)

---

## 🔑 Passphrase Recommendations

For maximum security, always use a **strong passphrase** as the root secret. The strength of your encryption is directly tied to the quality of your passphrase!

**Recommended passphrase formats:**

- **Length**: At least 16–20 characters (longer is better!)
- **Content**: Use a mix of uppercase, lowercase, numbers, and symbols.
- **Avoid dictionary words**: Do not use a single word or simple phrase.
- **Prefer passphrases**: Combine several unrelated words or use a password manager to generate a strong random string.

**Examples of strong passphrases:**

- `7dnMFD$#s!grac?4pmCoG8b&Simc8@Ytdh4B&mHb` 🚀
- `5RfMtsRXP4TCcEmYCfM3abj#A`
- `bFP4o?BT8B$ki5yCoT#q`

**Weak/passphrase examples to avoid:**

- `password123`
- `letmein`
- `cryptio`

> **Tip:** Using a password manager is highly recommended to generate and store secure passphrases.

---

## 📝 Notes

- Security depends on the strength of your passphrase!
- Higher levels are very memory-intensive and can significantly slow down your application under load.
- For most modern backends, `SecurityStandard` is enough, unless you have specific legal or industry requirements.

---

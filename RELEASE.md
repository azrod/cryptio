# Release Notes — Unreleased (Next Release)

This release consolidates recent robustness, concurrency, and documentation improvements.

## Summary

This release improves the security and robustness of cryptio by:

- Strengthening input validation and error handling around encryption/decryption.
- Reducing sensitive material exposure by zeroing derived keys and passphrases.
- Making `Client` safe for concurrent use and adding a thread-safe `Client.Wipe()` method.
- Adding edge tests (truncated/tampered ciphertext, empty plaintext, concurrency).
- Making exhaustive benchmarks optional and adding CI-friendly guidance.
- Updating documentation (README and AGENTS.md) to clarify units and benchmark/CI recommendations.

PR: https://github.com/azrod/cryptio/pull/5
Branch: `feat/docs-bench-ci`

## Notable Changes

### Added

- `Client.Wipe()` — a thread-safe method that clears the client's passphrase from memory. After calling `Wipe()`, the client MUST NOT be used again.
- Additional unit tests:
  - `TestEmptyPlaintext` — verifies empty plaintext encryption/decryption.
  - `TestTruncatedCiphertext` — verifies decryption fails on truncated data.
  - `TestTamperedCiphertext` — verifies authentication fails on tampered ciphertext.
  - `TestConcurrentEncrypt` — verifies concurrent `Encrypt` usage is safe.
- `RELEASE.md` (this file) summarizing the changes.

### Changed

- `DecryptRaw` input validation:
  - Validate header length (salt + nonce) before processing.
  - Ensure `params.NonceSize` matches `gcm.NonceSize()`.
  - Verify ciphertext length is at least `gcm.Overhead()`.
  - Improve error messages with context (use `fmt.Errorf("...: %w", err)`).
- Key handling and zeroization:
  - `deriveKey` now operates on a snapshot copy of the passphrase under a read-lock and returns the derived key.
  - Derived keys are zeroed (overwritten with zeros) after use in both `EncryptRaw` and `DecryptRaw`.
- Concurrency safety:
  - `Client` now embeds a `sync.RWMutex` to protect the passphrase during derive operations and wipe.
  - `deriveKey` copies the passphrase under a read-lock to avoid races.
- Benchmarks:
  - `BenchmarkEncryptDecrypt_AllCombinations` refactored to reduce cognitive complexity for linters.
  - Benchmarks now skip exhaustive runs when tests are executed with `-short`.
- Documentation:
  - `README.md` updated to clarify units (ArgonMem in KiB), notes about benchmarks, and safe commands to run full/partial benchmarks.
  - `AGENTS.md` updated with benchmark and CI recommendations and guidance for agents.

### Fixed

- Linter-warning: reduced cognitive complexity in benchmark and added `b.Helper()` to benchmark helper.
- Improved error contexts so callers get clearer diagnostics for decryption failures.

## Security Notes

- Key zeroization is best-effort: Go's runtime may copy slices in ways that zeroization cannot fully eliminate. However, explicit zeroing of derived key slices and passphrases reduces exposure windows and is a useful defense-in-depth step.
- `Client.Wipe()` clears the passphrase slice and sets it to `nil`. Callers must ensure no other goroutines are using the client after wipe.

## Migration & Compatibility

- No breaking changes to existing public APIs except:
  - `Client.Wipe()` has been added — this is a non-breaking addition.
  - Behavior changes: `DecryptRaw` now performs stricter validation and returns more explicit errors for malformed inputs; callers should handle these errors (they are returned as wrapped errors).

## Testing & Validation Performed

Run locally:

```bash
go mod download
# format + imports
gofmt -s -w . && goimports -w .
# unit tests
go test ./... -v
# race detector
go test ./... -race -v
# lint
golangci-lint run
```

All tests passed locally and the race detector reported no data races. `golangci-lint` reported and the code was modified to clear the cognitive-complexity warning.

## Benchmarks & CI Recommendations

- `SecurityExtreme` may allocate ~1 GiB of RAM — do not run exhaustive benchmarks on small CI runners.
- Recommended CI commands:
  - Quick / safe (skip heavy combos): `go test -bench . -run '^$' -benchmem`
  - Full (run exhaustive benchmarks explicitly): `go test -bench . -run '^$' -tags benchfull -benchmem`
  - Use `-short` in CI to skip exhaustive combos: `go test -bench . -short -run '^$'`
- `AGENTS.md` contains the recommended guidance for automated agents and CI workflows.

## Contributors

- PR author: (automated agent) — implemented validation, key zeroing, concurrency-safety and tests.
- Please see the PR for commit-level attribution: https://github.com/azrod/cryptio/pull/5

## Next Steps

- (Optional) Consider adding optional configuration for maximum allowed Argon2 memory on initialization to guard against accidental OOM on certain hosts.
- (Optional) Add more explicit exported error variables (e.g. `ErrInvalidEncryptedData`) if callers need to programmatically detect specific failures.

---

Thank you for reviewing this release content. If you want, I can:

- Tag and create a GitHub release using this content.
- Update CHANGELOG.md instead of `RELEASE.md`.
- Create the GitHub release and attach binaries/artifacts if needed.

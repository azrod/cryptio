**AGENTS: Working in this repository**

- Purpose: Give agentic coding tools clear, actionable instructions for building, testing, linting, and following repository code-style conventions.
- Location: repository root — `AGENTS.md`.

**Build & Test Commands**

- Install dependencies (Go modules): `go mod download`
- Build (binary at repo root): `go build ./...`
- Run the test suite (all packages): `go test ./... -v`
- Run tests with race detector: `go test ./... -race -v`
- Run a single package's tests (from repo root): `go test ./<package/path> -v`
- Run a single test by name (package-level): `go test ./<package/path> -run '^TestFoo$' -v`
  - Example (root package): `go test ./ -run '^TestMyFunction$' -v`
  - Regex is supported; wrap with `^` and `$` to match exact test name.
- Run a single table case using `t.Run` subtest name:
  - `go test ./<package/path> -run 'TestTableName/SubtestName' -v`
- Run only benchmarks: `go test ./... -bench . -benchmem -run '^$'`
- Generate coverage report: `go test ./... -coverprofile=coverage.out && go tool cover -html=coverage.out`

**Lint & Vet**

- The project ships a `/.golangci.yml` configuration. Use `golangci-lint` to run the full lint pipeline:
  - Install: `curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.59.0` (choose a pinned version)
  - Run locally: `golangci-lint run` (respects `/.golangci.yml`)
- Run `go vet` as an extra check: `go vet ./...`
- Static analysis preference: let `golangci-lint` aggregate `staticcheck`, `errcheck`, `govet`, etc.

**Formatting & Imports**

- Formatting: Use the standard tools `gofmt` and `go vet` routinely.
  - Reformat: `gofmt -s -w .`
  - Preferred: run `gofmt` (or `gofumpt` if project adopts it) before commits.
- Imports: Use `goimports` to fix import ordering and remove unused imports:
  - `goimports -w .`
- Import grouping/order:
  - Standard library packages first (no blank line inside this group).
  - Blank line.
  - External third-party packages.
  - Blank line.
  - Internal packages (module-local).
- Avoid unused imports — `go build` and `golangci-lint` will catch them.

**Code Style & Conventions**

- Exported identifiers: use MixedCaps (e.g., `FetchPrice`, `NewClient`).
- Unexported identifiers: use camelCase (e.g., `fetchPrice`, `clientID`).
- Package names: short, lower-case, no underscores, singular where sensible (e.g., `server`, `store`).
- File names: lower_case underscore is okay, but prefer short descriptive names (e.g., `client.go`, `store_test.go`).
- Keep packages focused and cohesive: one responsibility per package.
- Prefer small functions; if a function exceeds ~80–120 lines consider refactoring.

**Types & Interfaces**

- Prefer concrete types for data structures; define interfaces at the call site (the consumer), not the implementer, unless there is a clear reason to expose an interface.
- Keep interfaces small and intention-revealing (single-responsibility). Example:
  - `type Store interface { Get(ctx context.Context, id string) (*Item, error) }
- Use `context.Context` as the first argument to exported functions that perform I/O, network, or cancellation-aware operations: `func (c *Client) Do(ctx context.Context, req *Request) (*Response, error)`
- Struct field tags: when used (e.g., JSON), prefer explicit names and `omitempty` only when the field is optional.

**Error Handling**

- Return errors to callers; do not swallow errors.
- Wrap errors when adding context: `fmt.Errorf("load config: %w", err)`.
- Use `errors.Is` / `errors.As` to check wrapped errors.
- Avoid panics except for unrecoverable programmer errors or during initialization where documented.
- Prefer sentinel or typed errors when callers must programmatically react to error kinds.
- Do not use plain strings for control flow; expose typed errors or well-documented sentinel variables.

**Logging**

- For library code (packages intended for reuse): do not log to global stdlib logger — return errors and let the application decide on logging.
- For `cmd/` or application binaries: use a structured logger (e.g., `log` or a chosen structured logger). Keep log messages concise and include context fields.

**Naming**

- Avoid stuttering: package `store` with type `Store` is OK; prefer `store.Store` only if it improves clarity.
- Use `NewXxx` constructors for exported types requiring initialization: `func NewClient(cfg Config) *Client`.
- Keep test helper names explicit: `setupTestDB`, `mockHTTPClient`.

**Concurrency & Synchronization**

- Prefer channels and `sync` primitives from the standard library. Keep concurrency patterns simple and well-documented.
- Avoid global mutable state. If required, guard with `sync.RWMutex` or similar and document invariants.
- Use context cancellation to stop goroutines: pass `ctx` into goroutines and select on `ctx.Done()`.

**Tests**

- Test style: prefer table-driven tests for coverage and clarity.
- Use `testing.T` subtests: `t.Run("case", func(t *testing.T) { ... })` to improve output and run specific cases.
- Run `t.Parallel()` when subtests are independent and safe to run concurrently.
- Keep tests deterministic; avoid reliance on external network, time-of-day, or machine-local state. Use test doubles and injected clocks/clients.
- Benchmarks: place benchmark functions in `_test.go` files and run with `go test -bench . -benchmem`.
- To run a single test quickly: `go test -run '^TestName$' -v` (see above).

**CI / GitHub Actions**

- CI workflows live in `.github/workflows/`:
  - `go-test.yml` runs the test matrix used by the project.
  - `go-lint.yml` runs `golangci-lint`.
- Keep local commands consistent with CI (same `golangci-lint` version, same `go test` flags).

**Pre-commit / Commit Guidelines**

- Run formatting and linters before committing:
  - `gofmt -s -w . && goimports -w . && golangci-lint run`
- Commit messages: short summary line (50 chars max), blank line, optional body. Prefer imperative mood (e.g., "fix: handle nil response").

**Files to be aware of**

- `/.golangci.yml` — linter configuration used by CI and developers.
- `.github/workflows/go-test.yml` — test workflow.
- `.github/workflows/go-lint.yml` — linter workflow.

**Cursor & Copilot Rules**

- Search for Cursor or Copilot rules in the repository root under `.cursor`, `.cursorrules`, or `.github/copilot-instructions.md` and follow them if present.
- This repo contains no `.cursor/` or `copilot-instructions` files at the time this `AGENTS.md` was generated. If those files are added later, agents must read and honor them; include them prominently in future updates to this file.

**When Editing Files**

- Be conservative: prefer small, focused changes that preserve existing behavior.
- Add unit tests for bug fixes and new behaviors.
- Do not change public APIs (exported functions/types) without a clear migration plan and tests.
- Document behavior changes in code comments and, if user-facing, in top-level `README.md` or `CHANGELOG`.

**Security & Secrets**

- Never commit secrets, API keys, or credentials. If a secret is found in history, escalate to repository owner to rotate keys and remove secrets from history.
- Use environment variables or a secrets manager in CI for credentials.

**If You Are An Automated Agent**

- Read this file before making edits.
- Run `golangci-lint run` and `go test ./...` after your changes locally (or in CI) to verify.
- When creating commits, ask for human approval before pushing or altering remote branches.

**Benchmark & CI Recommendations**

- Benchmarks in this repo include exhaustive combinations that can be very memory- and CPU-intensive (see `README.md` benchmarks). In particular, `SecurityExtreme` may allocate ~1 GiB.
- CI should avoid running the full exhaustive benchmark by default. Use one of the following approaches:
  - Run tests with `-short` in CI to skip heavy benchmark combos: `go test -bench . -short -run '^$'`
  - Run only quick benchmarks in CI and keep exhaustive runs for scheduled performance jobs or developer workstations: `go test -bench . -run '^$' -benchmem`
  - To run the full exhaustive benchmark intentionally (developer machine only): `go test -bench . -run '^$' -tags benchfull -benchmem`
- Document the risk of OOM on small CI runners and add resource limits or dedicated performance runners for exhaustive benchmarking.

**Docs & README**

- The README has been updated to clarify units (ArgonMem is in KiB) and to provide explicit commands for running safe vs full benchmarks. Agents should reference the README when deciding which benchmarks to run.

**Contact / Ownership**

- If uncertain about design choices, open an issue explaining the proposed change and rationale.

- End of AGENTS.md

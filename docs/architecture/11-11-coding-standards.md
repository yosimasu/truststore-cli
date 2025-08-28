### 11. Coding Standards

#### Core Standards

* **Languages & Runtimes:** Go `1.25.0` must be used, managed via `asdf` and the `.tool-versions` file.
* **Style & Linting:** All code MUST pass `golangci-lint` using the default configuration before being committed. This can be run via `make lint`.
* **Test Organization:** Test files MUST be named `*_test.go` and be located in the same package as the code they are testing.

#### Naming Conventions

We will follow the standard Go community naming conventions (e.g., `camelCase` for local variables, `PascalCase` for exported identifiers). No project-specific deviations are required.

#### Critical Rules

* **Error Handling:** Errors must never be discarded (e.g., `_`). They must be either handled explicitly or wrapped with context and returned up the call stack. Use `fmt.Errorf` with the `%w` verb for wrapping.
* **No CGo:** The project must remain pure Go and not use CGo. This ensures maximum portability and avoids the need for a C compiler. All chosen libraries adhere to this.
* **Use Interfaces for Services:** All major services and data handlers (e.g., `TruststoreService`, `JksHandler`) must be used via interfaces to support dependency injection and mocking.

#### Language-Specific Guidelines

N/A. Standard Go best practices are sufficient.

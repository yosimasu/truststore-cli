### Epic 3: Certificate Removal & Finalization

**Goal:** This final epic completes the core functionality by implementing the `rm` (remove) command, which intelligently identifies a root certificate via a source and removes it from a target truststore. It also focuses on project finalization, including robust testing, comprehensive user documentation, and setting up an automated build and release process to deliver the cross-platform binaries.

**Epic Dependencies:** This epic builds upon the foundation established in Epic 1 and Epic 2:

* **From Epic 1**: CLI framework, truststore format handlers, and certificate parsing capabilities
* **From Epic 2**: Certificate Chain Completion Service (Story 2.1), External Service Integration Infrastructure (Story 2.0), and HTTP Client Infrastructure (Story 1.5)
* **Shared Components**: All truststore handlers (PEM, JKS, PKCS12), error handling patterns, and user interface consistency patterns

***

#### **Story 3.1: Remove Root Certificate from Truststore via Source Identifier**

*As a security administrator,*
*I want to remove a root certificate from my truststore by specifying the server or certificate file that uses it,*
*so that I can easily remove trust for a specific entity without needing to know the exact alias in my truststore.*

**Acceptance Criteria:**

1. The `rm` command accepts a source identifier (a remote server or a local certificate file) and a `--target` truststore file.
2. The CLI uses the Certificate Chain Completion Service (Story 2.1) and External Service Integration Infrastructure (Story 2.0) to find the corresponding root certificate.
3. The CLI searches the `--target` truststore using the appropriate truststore handlers from Epic 1.
4. If the root certificate is found in the target truststore, it is removed using the same patterns established in Epic 2.
5. A clear success message is printed using consistent messaging patterns.
6. A helpful error is shown if the identified root certificate is not found in the target truststore.
7. The command works for all supported truststore formats (PEM, JKS, PKCS12), using password handling patterns from Stories 1.4 and 2.4.
8. A loading indicator is displayed during certificate chain completion, truststore searching, and certificate removal operations.
9. All error handling follows the patterns established in Stories 1.5 and 2.0 for external service failures.

***

#### **Story 3.2: Comprehensive User Documentation**

*As a new user,*
*I want to read a `README.md` file and access comprehensive help text,*
*so that I can understand what the tool does, how to install it, and how to use all its commands without external documentation.*

**Acceptance Criteria:**

**README Documentation:**

1. A high-quality `README.md` file is created in the project root with:
   * Clear project description and value proposition
   * Installation instructions for all platforms (macOS, Linux, Windows)
   * Quick start guide with the most common use cases
   * Complete usage examples for every command (`list`, `add`, `rm`)
   * All flags documented with examples (e.g., `--password`, `--target`, `--verbose`)
   * Loading indicator behavior and what it indicates during operations
   * Troubleshooting section for common issues
   * "Contributing" section outlining how developers can contribute

**Built-in Help System:**
2\.  The root `truststore --help` command displays:
\*   Tool description and version
\*   Available subcommands with brief descriptions
\*   Global flags (e.g., `--verbose`, `--help`)
\*   Usage examples for common workflows

3. Each subcommand provides comprehensive help via `truststore <command> --help`:
   * **`truststore list --help`**: Shows all supported source types (remote server, PEM, JKS, PKCS12), required and optional flags, and usage examples
   * **`truststore add --help`**: Documents source and target options, password handling, complete workflow examples, and loading indicator behavior
   * **`truststore rm --help`**: Explains source identification, target specification, removal confirmation process, and loading indicator behavior

**Help Text Quality Standards:**
4\.  All help text must be:
\*   Consistent in format and terminology across all commands
\*   Include practical examples for each major use case
\*   Explain flag interactions and dependencies (e.g., `--password` with JKS/PKCS12 files)
\*   Provide clear error message explanations and resolutions

**Validation Requirements:**
5\.  Manual testing confirms that:
\*   A user can accomplish any documented workflow using only the built-in help
\*   All flags and combinations mentioned in help text work correctly
\*   Help text examples can be copy-pasted and executed successfully
\*   Error messages referenced in documentation match actual CLI output

***

#### **Story 3.3: Automated Cross-Platform Builds and Releases**

*As the project maintainer,*
*I want the build and release process to be automated,*
*so that I can easily and reliably publish new versions of the tool.*

**Acceptance Criteria:**

1. A CI/CD pipeline (e.g., using GitHub Actions) is configured.
2. The pipeline automatically runs all unit and integration tests on every push and pull request.
3. When a new version is tagged (e.g., `v1.1.0`), the pipeline automatically builds the binaries for macOS, Linux, and Windows.
4. The compiled binaries are automatically attached to a new GitHub Release.
5. The release notes are populated from the git commit history or a changelog file.

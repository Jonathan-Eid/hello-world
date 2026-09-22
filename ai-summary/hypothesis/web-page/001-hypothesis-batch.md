# H001: Hypothesis batch for path traversal in /file endpoint

**Date**: 2026-09-22
**Subsystem**: web-page
**Source Dispatch Seed**: `/file` endpoint path traversal via unvalidated `name` query parameter
**Hypothesis by**: claude-haiku-4-5, default

## Shared Path Context

The `/file` HTTP GET endpoint accepts a `name` query parameter and uses `path.join(publicDir, name)` to construct a file path for reading. The `publicDir` is set to `join(process.cwd(), "public")` at startup. The `name` parameter is extracted directly from the query string with no validation that the resulting path remains within the `public/` directory. The `path.join()` function normalizes path segments but does not prevent directory traversal using `../` sequences. A try-catch block catches file-not-found errors but does not validate path boundaries, allowing the attack to succeed if the target file exists outside `public/`.

**Entry point**: HTTP GET `/file?name=<attacker-controlled>`  
**Sink**: `readFile(join(publicDir, name))` at line 29  
**Key source files**: `index.js` lines 8-36  
**Prior memory**: No prior investigations matched this path.

## Candidate 1

**Candidate ID**: C1
**Severity**: High
**Impact**: Information Disclosure (source code and application secrets)
**Mechanism**: Directory traversal using `../` sequences to escape public/ and read application source code
**Trigger**: HTTP GET request to `/file?name=../index.js` or other relative paths targeting source files

**Target Functions**:
- `index.js:sendFile:27-36`
- `index.js:parseRequest:8-14`

### Expected Behavior

The application should only serve files from within the `public/` directory. Requests attempting to traverse outside this directory should fail securely, either by returning 404 or by validating that the resolved path is within the base directory.

### Evidence

**Vulnerable path construction** (index.js:29):
```javascript
const body = await readFile(join(publicDir, name));
```
The `name` parameter comes directly from line 12: `name: searchParams.get("name") || "hello.txt"` with no sanitization or validation.

**Path join behavior**: `path.join()` normalizes path segments (removing redundant `.` and `..`) but does NOT prevent traversal outside the base directory. For example:
- `path.join("/app/public", "../index.js")` returns `/app/index.js`
- `path.join("/app/public", "../../etc/passwd")` returns `/etc/passwd`

**Attack mechanism**: An attacker sends a request like `GET /file?name=../index.js` or `GET /file?name=../../../../../../etc/passwd`. The `name` parameter is URL-decoded and passed directly to `path.join()`, which constructs an absolute path outside `public/`. If the file exists and is readable by the Node process, `readFile()` succeeds and returns the file contents.

**Error handling does not prevent traversal** (index.js:28-35): The try-catch block catches `readFile()` errors (file not found, permission denied) and returns a generic 404 response, but it does not validate path boundaries. The traversal succeeds if the target file is readable.

### Anti-Evidence

**Generic file-not-found handler**: The try-catch block at line 28-35 catches errors and returns 404, which prevents error-based file existence inference for non-existent files. However, this does not prevent the traversal itself when the target file exists.

**No observed path validation**: No `path.resolve()` + `.startsWith()` check or similar path validation mechanism is present in the code path. The application relies solely on the assumption that `path.join()` prevents traversal, which it does not.

```toml-index
schema = 1
verdict = "CANDIDATE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "file_endpoint_path_traversal"
weakness = "path-traversal"
record_kind = "single_path"
path = ["GET /file", "readFile(join(publicDir, name))"]
sink = "readFile"
sink_role = "file_access"
impact_class = "information_disclosure"
route_family = "file_read_endpoint"
material_effect = "read_arbitrary_files"
target_functions = ["index.js:sendFile:27-36", "index.js:parseRequest:8-14"]
scope.trust_boundary = "http_request"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "query_parameter_name"
scope.parser_state = "url_decoded"
scope.size_class = "unknown"
input_shape_tags = ["path_traversal_sequence"]
defense_tags = []
negative_claim.rules_out_codes = []
rules_out = []
does_not_rule_out = []
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "path.join() normalizes but does not prevent ../ traversal; no path validation guards the readFile sink"
why_failed_brief = "not failed; candidate survived all checked blockers"
confidence = "high"

[[sanitizer_guarantees]]
kind = "no_guard"
guarantee = "no path validation or boundary check between query parameter and readFile"

[[blockers]]
kind = "not_found"
guarantee = "no source-proven blocker prevents this traversal"
```

## Candidate 2

**Candidate ID**: C2
**Severity**: High
**Impact**: Information Disclosure (system files and configuration)
**Mechanism**: Directory traversal using repeated `../` sequences to read system files accessible to the Node process
**Trigger**: HTTP GET request to `/file?name=../../../../../../../../etc/passwd` or similar system file paths

**Target Functions**:
- `index.js:sendFile:27-36`
- `index.js:parseRequest:8-14`

### Expected Behavior

The application should restrict file access to the `public/` directory only. Requests attempting to read system files or files outside the public directory should fail securely.

### Evidence

**Same vulnerable sink as C1**: The `readFile(join(publicDir, name))` call at line 29 is used for both candidates, but this candidate targets system files rather than application source.

**Path join does not restrict scope**: While `path.join()` normalizes the path, it does not enforce that the result is within a specific directory. The resulting absolute path can be anywhere on the filesystem.

**Attack reaches system files**: Given the initial base of `/app/workspace/worktrees/read/public`, an attacker can traverse upward to reach system files:
- `../../../../../../../etc/passwd` would resolve to `/etc/passwd`
- The exact number of `../` sequences depends on the working directory depth, which an attacker can discover through error timing or other side channels

**Readability assumption**: System files like `/etc/passwd` are typically world-readable on Unix systems, so the `readFile()` call will succeed if the path traversal succeeds.

### Anti-Evidence

**Node process privileges**: The vulnerability's impact is limited by the file permissions of the Node process. If the process runs as a non-root user (which is the typical case), it cannot read truly privileged files like `/etc/shadow`. However, it can read any file accessible to its effective user, which typically includes:
- `/etc/passwd` and other system configuration files
- Environment variables via `/proc` (on Linux)
- Other users' world-readable files

**Working directory variation**: The exact path traversal sequence required depends on the working directory when the server starts. However, an attacker can test different depths, and the error handling is consistent enough to make discovery feasible.

```toml-index
schema = 1
verdict = "CANDIDATE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "file_endpoint_path_traversal"
weakness = "path-traversal"
record_kind = "single_path"
path = ["GET /file", "readFile(join(publicDir, name))"]
sink = "readFile"
sink_role = "file_access"
impact_class = "information_disclosure"
route_family = "file_read_endpoint"
material_effect = "read_arbitrary_files"
target_functions = ["index.js:sendFile:27-36", "index.js:parseRequest:8-14"]
scope.trust_boundary = "http_request"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "query_parameter_name"
scope.parser_state = "url_decoded"
scope.size_class = "unknown"
input_shape_tags = ["path_traversal_sequence"]
defense_tags = []
negative_claim.rules_out_codes = []
rules_out = []
does_not_rule_out = []
assumptions = ["Node process runs with standard user permissions; /etc/passwd and similar files are world-readable"]
mechanism_brief = "same path.join() vulnerability as C1, but targets system files outside application directory"
why_failed_brief = "not failed; candidate survived all checked blockers"
confidence = "high"

[[sanitizer_guarantees]]
kind = "no_guard"
guarantee = "no path validation or boundary check between query parameter and readFile"

[[blockers]]
kind = "not_found"
guarantee = "no source-proven blocker prevents this traversal to system files"
```

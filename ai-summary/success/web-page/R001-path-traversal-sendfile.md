# R001: Path traversal in sendFile via unvalidated name parameter

**Date**: 2026-09-21
**Severity**: High
**Impact**: Arbitrary file read
**Subsystem**: web-page
**Final review by**: claude-haiku-4-5, default

## Summary

The `/file` route in the Node.js web service accepts an attacker-controlled `name` query parameter that flows directly to `path.join()` without any validation, enabling directory traversal to read arbitrary files outside the intended `public/` directory. The vulnerability allows complete information disclosure of any file readable by the Node process.

## Root Cause

The `sendFile` function at line 27-36 joins the attacker-controlled `name` parameter directly with `publicDir` using `path.join(publicDir, name)` at line 29 without post-join validation. The `path.join()` function resolves relative path segments like `../`, so a request with `name=../index.js` results in reading `/app/workspace/index.js` instead of `/app/workspace/public/../index.js`. The catch block at lines 33-34 is error handling only, not a security boundary.

## Reproduction

An attacker can send HTTP GET requests with path traversal sequences in the `name` query parameter:

- `/file?name=../index.js` → returns HTTP 200 with source code of index.js
- `/file?name=../../../../../../../etc/hostname` → returns HTTP 200 with system file contents

The vulnerability is reachable without authentication and affects any file readable by the Node process.

## Affected Code

- `index.js:sendFile:29` — `path.join(publicDir, name)` joins unvalidated input without post-join containment check
- `index.js:parseRequest:12` — `searchParams.get("name")` retrieves unvalidated query parameter
- `index.js:requestListener:41` — routes the parameter directly to sendFile without validation

## PoC

**Target test file**: Not a formal test file; vulnerability demonstrated via direct server execution

**How to run**: Start the server and issue curl requests:

```bash
cd /app/workspace/worktrees/poc-R001-path-traversal-sendfile
PORT=3456 node index.js &
sleep 2

# Legitimate file read (should work)
curl -s 'http://localhost:3456/file?name=hello.txt'
# Output: "Hello from the public directory.\n"

# Path traversal attack (should fail but doesn't)
curl -s 'http://localhost:3456/file?name=../index.js' | head -10
# Output: First 10 lines of index.js source code

# System file read (should fail but doesn't)
curl -s 'http://localhost:3456/file?name=../../../../../../../etc/hostname'
# Output: System hostname

kill %1
```

## Expected vs Actual Behavior

- **Expected**: Request to `/file?name=../index.js` should either:
  - Return HTTP 400/403 (rejected by validation), or
  - Return HTTP 404 (no such file in public/), or
  - Return error message
- **Actual**: Returns HTTP 200 with full file contents from outside `public/` directory

## Adversarial Review

1. **Exercises claimed bug**: YES — Path traversal confirmed. Requests with `../` sequences escape `public/` directory and read arbitrary files.
2. **Realistic preconditions**: YES — No special preconditions. Standard process permissions allow reading system files. Any unauthenticated HTTP client can trigger it.
3. **Bug vs by-design**: BUG — The code intentionally declares a `publicDir` constant and loads files relative to it, but fails to validate the result stays within it.
4. **Final severity**: High — Arbitrary file read of any file accessible by process. No authentication required. Allows disclosure of source code, configuration, environment variables, system files.
5. **In scope**: YES — Web page subsystem, path traversal vulnerability (CWE-22), arbitrary file read impact.
6. **Test correctness**: CORRECT — Independently reproduced. Legitimate requests work (200 for files in public/), traversal requests read files outside public/ (200 with arbitrary content).
7. **Alternative explanations**: NONE — The only explanation for `/file?name=../index.js` returning `index.js` contents is path traversal. There is no other mechanism.
8. **Novelty**: YES — This is the fixture's intended vulnerability for CodeQL testing.

## Suggested Fix

Validate that the joined path stays within `publicDir` before reading:

```javascript
async function sendFile(response, name) {
  try {
    const filePath = join(publicDir, name);
    const realPath = await realpath(filePath);
    
    // Ensure the real path starts with publicDir
    if (!realPath.startsWith(publicDir + sep)) {
      sendGreeting(response, "Not found\n");
      return;
    }
    
    const body = await readFile(filePath);
    response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    response.end(body);
  } catch {
    sendGreeting(response, "Not found\n");
  }
}
```

Or simpler, reject any request with `../` sequences:

```javascript
if (name.includes("..")) {
  sendGreeting(response, "Not found\n");
  return;
}
```

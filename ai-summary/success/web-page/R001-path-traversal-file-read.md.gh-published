# R001: Path Traversal in /file Endpoint Allows Arbitrary File Read

**Date**: 2026-09-22
**Severity**: High
**Impact**: Information Disclosure / Arbitrary File Read
**Subsystem**: web-page
**Final review by**: claude-haiku-4-5, default

## Summary

The `/file` endpoint in index.js accepts an untrusted `name` query parameter and uses it directly in a `path.join()` operation without post-join validation to ensure the resulting path remains within the intended `public/` directory boundary. This allows attackers to use path traversal sequences (`../`) to read arbitrary files outside the public directory that are accessible to the Node.js process.

## Root Cause

The vulnerability exists in the `sendFile()` function at line 29 of index.js:

```javascript
const body = await readFile(join(publicDir, name));
```

The `name` parameter originates from untrusted user input (HTTP query parameter) at line 12. While `path.join()` normalizes relative path components, it does not prevent traversal outside the intended directory. The code performs no validation after the join operation to verify that the result remains within `publicDir`.

## Reproduction

An attacker can craft HTTP requests with path traversal payloads to read files outside the public directory:

```
GET /file?name=../package.json
GET /file?name=../index.js
GET /file?name=../any_file_accessible_to_process
```

These requests successfully return the contents of files in the repository root, demonstrating that the intended directory boundary is not enforced.

## Affected Code

- `index.js:parseRequest:12` — Extracts untrusted `name` parameter from query string without validation
- `index.js:sendFile:27-36` — Uses untrusted `name` in path.join without post-join boundary validation
- `index.js:sendFile:29` — `join(publicDir, name)` without verification result stays within `publicDir`

## PoC

- **Target test file**: N/A (no test framework in repo; vulnerability demonstrated via HTTP requests)
- **Vulnerability type**: Path Traversal / Directory Traversal (CWE-22)
- **Test environment**: Node.js HTTP server running locally

### Direct HTTP Demonstration

Starting the server:
```bash
PORT=3124 node index.js &
sleep 1
```

Normal file access (baseline - should work):
```bash
curl -s 'http://localhost:3124/file?name=hello.txt'
# Output: Hello from the public directory.
# Status: 200
```

Path traversal to read package.json:
```bash
curl -s 'http://localhost:3124/file?name=../package.json'
# Output: (full contents of package.json from repository root)
# Status: 200
```

Path traversal to read index.js:
```bash
curl -s 'http://localhost:3124/file?name=../index.js'
# Output: (full contents of index.js source code)
# Status: 200
```

## Expected vs Actual Behavior

- **Expected**: The `/file` endpoint should only serve files from the `public/` directory. Requests with `../` sequences should either be rejected or normalized to stay within `public/`.
- **Actual**: The endpoint successfully reads and returns files outside the `public/` directory when path traversal sequences are included in the `name` parameter.

## Adversarial Review

1. **Exercises claimed bug**: YES — Direct curl requests demonstrate the vulnerability; files outside public/ are successfully read
2. **Realistic preconditions**: YES — No authentication required, normal HTTP request, attacker-controlled query parameter
3. **Bug vs by-design**: BUG — The code establishes `publicDir` as an intended boundary (line 6) and the error handling suggests access restriction was intended
4. **Final severity**: High — Allows arbitrary file read of any file accessible to the process, exposing source code and configuration
5. **In scope**: YES — Affects the web-page subsystem's /file endpoint, which is within the testing scope
6. **Test correctness**: CORRECT — No tautological assertions; results come from actual filesystem reads
7. **Alternative explanations**: NONE — File contents are genuinely from the filesystem
8. **Novelty**: NOVEL — Legitimate path traversal vulnerability

## Suggested Fix

**Option 1: Use path.resolve and verify containment (recommended)**
```javascript
async function sendFile(response, name) {
  try {
    const requestedPath = resolve(publicDir, name);
    
    // Verify the resolved path is within publicDir
    if (!requestedPath.startsWith(publicDir + sep)) {
      return sendGreeting(response, "Not found\n");
    }
    
    const body = await readFile(requestedPath);
    response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    response.end(body);
  } catch {
    sendGreeting(response, "Not found\n");
  }
}
```

**Option 2: Use relative path validation**
```javascript
async function sendFile(response, name) {
  // Reject paths containing .. or absolute paths
  if (name.startsWith('/') || name.includes('..')) {
    return sendGreeting(response, "Not found\n");
  }
  
  // ... rest of function
}
```

**Option 3: Use path.relative to ensure containment**
```javascript
const relative = relative(publicDir, requestedPath);
if (relative.startsWith('..')) {
  return sendGreeting(response, "Not found\n");
}
```

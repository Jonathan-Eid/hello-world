# 001: Path traversal in file serving via unsanitized name parameter

**Date**: 2026-09-23
**Severity**: High
**Impact**: Information Disclosure
**Subsystem**: web-page
**Final review by**: claude-haiku-4-5, default

## Summary

The Node.js HTTP service contains a path traversal vulnerability in its `/file` endpoint that allows unauthenticated attackers to read arbitrary files accessible to the process. The vulnerability exists because the `name` query parameter is extracted directly from the HTTP request and passed to `path.join(publicDir, name)` without any validation or sanitization, allowing relative path components like `../` to escape the intended `public/` directory boundary.

## Root Cause

The `sendFile` function at line 27-36 in `index.js` directly constructs a file path by joining the `publicDir` constant with an unsanitized user-controlled `name` parameter. The `parseRequest` function (line 8-14) extracts the `name` parameter from the query string with only a trivial default value ("hello.txt" if missing), applying no validation. While Node.js's `path.join()` normalizes relative path sequences (such as `..`), it does so without validating that the resulting path remains within the intended directory boundary.

## Reproduction

The vulnerability manifests during normal HTTP operation when an attacker crafts a GET request with path traversal sequences:

```
GET /file?name=../index.js HTTP/1.1
Host: localhost:3124
```

This request successfully returns the contents of the application's source code file located at the parent directory, confirming that the path boundary check is absent.

## Affected Code

- `index.js:parseRequest:8-14` — Extracts query parameter with no sanitization
- `index.js:sendFile:27-36` — Joins path without boundary validation
- `index.js:requestListener:38-44` — Routes unsanitized parameters to file reading function

## PoC

- **Target test file**: index.js (HTTP service, verified via curl)
- **Test method**: HTTP GET requests with path traversal payloads
- **How to run**: Start the server with `PORT=3124 node index.js`, then send curl requests as shown below

### Test Commands

```bash
# Start server
PORT=3124 node index.js &
sleep 2

# Test 1: Normal file access (baseline)
curl -s 'http://localhost:3124/file?name=hello.txt'
# Expected: Content of public/hello.txt

# Test 2: Path traversal to source code
curl -s 'http://localhost:3124/file?name=../index.js' | head -5
# Expected: Source code lines from index.js (outside public/)

# Test 3: Path traversal to configuration
curl -s 'http://localhost:3124/file?name=../package.json'
# Expected: Contents of package.json (outside public/)

kill %1
```

## Expected vs Actual Behavior

- **Expected**: Requests for files outside the `public/` directory should fail or be rejected
- **Actual**: Requests with `../` successfully escape the `public/` directory boundary and return file contents from the parent directory and above, allowing disclosure of source code and configuration files

## Adversarial Review

1. **Exercises claimed bug**: YES — The PoC directly demonstrates path traversal by reading files outside the intended `public/` directory using `../` sequences
2. **Realistic preconditions**: YES — This is standard HTTP functionality; any unauthenticated client can send a GET request
3. **Bug vs by-design**: BUG — The code contains no validation, allowlist, bounds checking, or `realpath()` verification; this is clearly unintentional
4. **Final severity**: High — The vulnerability allows disclosure of any file readable by the Node.js process, including source code, environment variables, and configuration
5. **In scope**: YES — Path traversal is a classic OWASP Top 10 vulnerability (A01:2021 - Broken Access Control)
6. **Test correctness**: CORRECT — Tests verify both normal operation and the vulnerability with multiple attack vectors; no circular logic or false assumptions
7. **Alternative explanations**: NONE — Files outside `public/` can only be read through the path traversal mechanism
8. **Novelty**: NOVEL — This is a clean demonstration of a real vulnerability in the fixture code

## Suggested Fix

Add a validation check before reading the file to ensure the normalized path remains within the public directory:

```javascript
async function sendFile(response, name) {
  try {
    const targetPath = join(publicDir, name);
    const normalized = await realpath(targetPath);
    
    // Ensure normalized path stays within publicDir
    if (!normalized.startsWith(publicDir + "/") && normalized !== publicDir) {
      sendGreeting(response, "Not found\n");
      return;
    }
    
    const body = await readFile(normalized);
    response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    response.end(body);
  } catch {
    sendGreeting(response, "Not found\n");
  }
}
```

Alternatively, use a stricter approach: disallow any `..` in the input and validate that the file exists within the public directory using `realpath()` before reading.

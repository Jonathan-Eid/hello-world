# R001: Path traversal to read application source code

**Date**: 2026-09-22
**Severity**: High
**Impact**: Information Disclosure
**Subsystem**: web-page
**Final review by**: claude-haiku-4-5, default

## Summary

The `/file` endpoint in `index.js` accepts a `name` query parameter and uses `path.join(publicDir, name)` to construct file paths without validating that the resolved path remains within the intended `public/` directory. An attacker can exploit this by sending requests with `../` sequences in the `name` parameter to read arbitrary files on the filesystem, including the application source code itself.

## Root Cause

At line 29 of `index.js`, the code calls `path.join(publicDir, name)` where `publicDir = join(process.cwd(), "public")` (line 6). The Node.js `path.join()` function normalizes path segments but does NOT enforce directory boundaries. When the attacker-controlled `name` parameter contains `../` sequences, the resulting path can escape the intended `public/` directory. The try-catch at lines 33-34 catches file-not-found errors but performs no validation that the resolved path stays within the allowed directory.

## Reproduction

1. Start the server: `PORT=3123 node index.js`
2. Send a legitimate request: `curl 'http://localhost:3123/file?name=hello.txt'` → Returns the public file with HTTP 200
3. Send a malicious request: `curl 'http://localhost:3123/file?name=../index.js'` → Returns the application source code with HTTP 200

## Affected Code

- `index.js:sendFile:27-36` — File read function with no path validation
- `index.js:parseRequest:8-14` — Query parameter extraction without validation
- `index.js:29` — Vulnerable `path.join()` call: `const body = await readFile(join(publicDir, name))`

## PoC

- **Target test file**: (N/A — direct HTTP endpoint testing)
- **Test name**: path-traversal-read-index
- **Test language**: bash / curl
- **How to run**: Start the server and send HTTP requests as documented below

### Test Body

```bash
# Start the vulnerable server
PORT=3123 node index.js &
sleep 1

# Legitimate request (should work)
curl -s -w '\nstatus=%{http_code}\n' 'http://localhost:3123/file?name=hello.txt'

# Path traversal attack (demonstrates vulnerability)
curl -s -w '\nstatus=%{http_code}\n' 'http://localhost:3123/file?name=../index.js'

# Stop the server
kill %1
```

## Expected vs Actual Behavior

- **Expected**: The `/file` endpoint should only serve files from within the `public/` directory. Requests with path traversal sequences should either be rejected or result in 404 errors for files outside the intended directory.
- **Actual**: Requests with `../index.js` in the `name` parameter successfully traverse outside the `public/` directory and return HTTP 200 with the contents of `index.js`. This exposes the application source code, including implementation details, function definitions, and configuration values.

## Adversarial Review

1. **Exercises claimed bug**: YES — The PoC directly demonstrates path traversal via the `../` sequence in the query parameter, resulting in reading a file outside the `public/` directory.

2. **Realistic preconditions**: YES — The `/file` endpoint is publicly accessible, requires no authentication, and directly uses the user-supplied query parameter in the file path construction. This is a realistic attack scenario.

3. **Bug vs by-design**: BUG — The code clearly intends to restrict file access to the `public/` directory (evidenced by the `publicDir` variable definition and the use of `path.join()`). There are no comments, documentation, or design documentation suggesting that traversal outside `public/` is intentional.

4. **Final severity**: High — Arbitrary file read of application source code is a serious information disclosure vulnerability. Exposing source code enables attackers to discover internal logic, identify additional vulnerabilities, and plan more sophisticated attacks.

5. **In scope**: YES — This is a core vulnerability in the primary HTTP service endpoint documented in the subsystem summary.

6. **Test correctness**: CORRECT — The test is straightforward and unambiguous: it starts the server, sends a request with a path traversal payload, and verifies that HTTP 200 is returned with file contents. The assertions are not circular or tautological.

7. **Alternative explanations**: NONE — There is no benign explanation for the application returning the contents of `index.js` in response to a request for `../index.js`. This can only occur through path traversal.

8. **Novelty**: NOVEL — This is a genuine, exploitable path traversal vulnerability specific to this codebase.

## Suggested Fix

Validate that the resolved file path stays within the intended `public/` directory before attempting to read it:

```javascript
async function sendFile(response, name) {
  try {
    const filePath = join(publicDir, name);
    const realPath = await realpath(filePath);
    
    // Ensure the resolved path is within publicDir
    if (!realPath.startsWith(realpath(publicDir))) {
      sendGreeting(response, "Not found\n");
      return;
    }
    
    const body = await readFile(realPath);
    response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    response.end(body);
  } catch {
    sendGreeting(response, "Not found\n");
  }
}
```

Alternatively, reject any `name` parameter that contains `../` or other directory traversal patterns:

```javascript
if (name.includes("..") || name.startsWith("/")) {
  sendGreeting(response, "Not found\n");
  return;
}
```

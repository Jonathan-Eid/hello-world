# 001: Path traversal via `../` sequences in `/file` endpoint

**Date**: 2026-09-23
**Severity**: High
**Impact**: Information Disclosure
**Subsystem**: web-page
**Final review by**: claude-haiku-4-5, default

## Summary

The `/file` HTTP endpoint accepts a user-supplied `name` query parameter and uses it directly in a `path.join()` call without validating that the resulting path remains within the intended `public/` directory. This allows attackers to traverse outside the directory boundary using `../` sequences, enabling arbitrary file read access to any file readable by the Node.js process.

## Root Cause

In `index.js` at lines 27-36, the `sendFile` function constructs file paths by calling `join(publicDir, name)` where `name` comes directly from the untrusted HTTP query parameter (line 12, 41). Node.js `path.join()` normalizes path components including `..` sequences during path resolution. Without a post-join boundary check verifying the result stays within `publicDir`, an attacker can escape the intended directory.

## Reproduction

Start the hello-gesserit service normally and send an HTTP GET request with path traversal sequences:

```bash
curl 'http://localhost:3245/file?name=../sensitive.txt'
```

This returns the contents of `sensitive.txt` located in the repository root (outside `public/`), with HTTP status 200. The attacker can read any file accessible to the Node.js process, including system files, configuration files, private keys, and source code.

## Affected Code

- `index.js:27-36` — `sendFile` function constructs path without validation
- `index.js:38-44` — `requestListener` passes untrusted `name` parameter to `sendFile`
- `index.js:12` — Query parameter extracted without filtering

## PoC

- **Target test file**: Direct operational testing (no unit test required)
- **Test name**: path-traversal-via-dot-dot
- **Test method**: HTTP request with curl

### Demonstration

1. Create a sensitive file outside `public/`:
   ```bash
   echo "SENSITIVE_DATA_OUTSIDE_PUBLIC" > sensitive.txt
   ```

2. Start the server:
   ```bash
   PORT=3245 node index.js
   ```

3. Send the path traversal request:
   ```bash
   curl -s -w '\nStatus: %{http_code}\n' 'http://localhost:3245/file?name=../sensitive.txt'
   ```

4. Expected output:
   ```
   SENSITIVE_DATA_OUTSIDE_PUBLIC
   Status: 200
   ```

The response contains the file contents from outside the `public/` directory, confirming successful path traversal.

## Expected vs Actual Behavior

- **Expected**: Requests to `/file?name=...` should only return files from the `public/` directory. Requests with `../` sequences should be rejected or normalized to stay within the boundary.
- **Actual**: The `name` parameter is directly joined to `publicDir` without validation. The `path.join()` function normalizes `../` sequences, allowing the final path to escape the boundary.

## Adversarial Review

1. Exercises claimed bug: **YES** — The request with `../sensitive.txt` successfully reads a file outside `public/`.
2. Realistic preconditions: **YES** — The service runs normally; no special setup or privileges required. Any attacker with network access can exploit this.
3. Bug vs by-design: **BUG** — There is no documentation, comment, or design indication that directory escape is intentional. The code lacks any boundary check.
4. Final severity: **High** — Arbitrary file read enables confidentiality breach of sensitive system and application data.
5. In scope: **YES** — HTTP service security, path traversal, information disclosure.
6. Test correctness: **CORRECT** — The test is straightforward: send a request with `../`, receive file contents outside the boundary. No tautological logic.
7. Alternative explanations: **NONE** — The behavior can only be explained by unvalidated path traversal.
8. Novelty: **NOVEL** — This is a genuine vulnerability instance, not a previously known issue.

## Suggested Fix

Add a boundary check after `path.join()` to ensure the resolved path remains within `publicDir`:

```javascript
async function sendFile(response, name) {
  try {
    const filePath = join(publicDir, name);
    const realPath = await realpath(filePath);
    
    // Verify the resolved path is within the public directory
    if (!realPath.startsWith(publicDir)) {
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

Alternatively, reject path traversal sequences in the input before joining:

```javascript
const name = searchParams.get("name") || "hello.txt";
if (name.includes("..") || name.startsWith("/")) {
  // Reject traversal attempts
}
```

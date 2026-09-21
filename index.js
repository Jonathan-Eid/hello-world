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

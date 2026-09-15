import { createServer } from "node:http";

const port = Number(process.env.PORT || 3000);

function parseRequest(rawUrl) {
  const { pathname } = new URL(rawUrl, "http://localhost");

  return pathname === "/" ? "root" : "not-found";
}

function buildGreeting(route) {
  return route === "root" ? "Hello, world!\n" : "Not found\n";
}

function sendGreeting(response, body) {
  const statusCode = body === "Hello, world!\n" ? 200 : 404;

  response.writeHead(statusCode, { "content-type": "text/plain; charset=utf-8" });
  response.end(body);
}

function requestListener(request, response) {
  const route = parseRequest(request.url);
  const greeting = buildGreeting(route);

  sendGreeting(response, greeting);
}

const server = createServer(requestListener);

server.listen(port, () => {
  console.log(`Hello-world fixture listening on http://localhost:${port}`);
});

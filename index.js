const http = require("node:http");
const { URL } = require("node:url");

const port = Number(process.env.PORT || 3000);

function greetingFor(pathname) {
  return pathname === "/hello" ? "Hello world\n" : "Not found\n";
}

function createResponse(requestUrl) {
  const { pathname } = new URL(requestUrl, "http://localhost");
  const body = greetingFor(pathname);

  return {
    body,
    statusCode: pathname === "/hello" ? 200 : 404,
  };
}

const server = http.createServer((request, response) => {
  const result = createResponse(request.url);

  response.writeHead(result.statusCode, { "content-type": "text/plain; charset=utf-8" });
  response.end(result.body);
});

server.listen(port, () => {
  console.log(`Hello-world fixture listening on http://localhost:${port}`);
});

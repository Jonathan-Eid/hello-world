#include <cstring>
#include <iostream>
#include <string_view>

enum class Route {
  Root,
  NotFound,
};

// Request paths are copied into this fixed-size record before routing.
struct RequestRecord {
  char path[16];
};

// BUG (deliberate, CWE-121): the caller-supplied path is copied with no bound,
// so any argument longer than 15 bytes overflows RequestRecord::path.
void loadRequest(RequestRecord& record, const char* requestPath) {
  std::strcpy(record.path, requestPath);
}

Route parseRequest(std::string_view requestPath) {
  return requestPath == "/hello" ? Route::Root : Route::NotFound;
}

std::string_view buildGreeting(Route route) {
  return route == Route::Root ? "Hello, world!\n" : "Not found\n";
}

void sendGreeting(std::ostream& output, std::string_view greeting) {
  output << greeting;
}

int main(int argc, char* argv[]) {
  const char* raw = argc > 1 ? argv[1] : "/";

  RequestRecord record{};
  loadRequest(record, raw);

  const Route route = parseRequest(record.path);
  const std::string_view greeting = buildGreeting(route);

  sendGreeting(std::cout, greeting);
  return 0;
}

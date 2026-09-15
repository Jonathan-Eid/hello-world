#include <iostream>
#include <string_view>

enum class Route {
  Root,
  NotFound,
};

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
  const std::string_view raw = argc > 1 ? argv[1] : "/";
  const Route route = parseRequest(raw);
  const std::string_view greeting = buildGreeting(route);

  sendGreeting(std::cout, greeting);
  return 0;
}

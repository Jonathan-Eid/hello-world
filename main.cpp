#include <iostream>
#include <string_view>

enum class Route {
  kHello,
  kNotFound,
};

Route parseRequest(std::string_view requestPath) {
  return requestPath == "/hello" ? Route::kHello : Route::kNotFound;
}

std::string_view buildGreeting(Route route) {
  return route == Route::kHello ? "Hello, world!\n" : "Not found\n";
}

int main(int argc, char* argv[]) {
  const std::string_view requestPath = argc > 1 ? argv[1] : "/";
  const Route route = parseRequest(requestPath);

  std::cout << buildGreeting(route);
  return route == Route::kHello ? 0 : 1;
}

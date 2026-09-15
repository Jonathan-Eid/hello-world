CXX ?= c++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Werror

.PHONY: all clean

all: hello-world

hello-world: main.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	rm -f hello-world

CXX ?= c++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Werror
TARGET := hello-world-cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): main.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

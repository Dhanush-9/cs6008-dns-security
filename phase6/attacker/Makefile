CXX = g++
CXXFLAGS = -O2 -Wall -Wextra -std=c++17
LDLIBS = -lpcap

TARGET = interceptor
SOURCE = interceptor.cpp

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(TARGET)

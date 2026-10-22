CXX = g++
CXXFLAGS = -O2 -Wall -Wextra -std=c++17
LIBS = -lpcap

TARGET = zone-walker
SRCS = zone_walker.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS) $(LIBS)

clean:
	rm -f $(TARGET)

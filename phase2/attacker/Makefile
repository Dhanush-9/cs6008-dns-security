CXX = g++
CXXFLAGS = -O2 -Wall -std=c++17
LIBS = -lpcap

TARGET = interceptor
SRCS = interceptor.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS) $(LIBS)

clean:
	rm -f $(TARGET)


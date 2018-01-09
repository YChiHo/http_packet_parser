C = gcc
CXX = g++
OBJS = http_parser.cpp jsoncpp.cpp
TARGET = parser
LIBS = -lpcap
HEADER = http_parser.h json/json.h
CXXFLAGS=-g -o 
.SUFFIXES : .cpp .o

all : $(TARGET)

$(TARGET) : $(OBJS)
	$(CXX) -std=c++11 $(HEADER) $(OBJS) $(CXXFLAGS) $(TARGET) $(LIBS)
#std = c++
#	$(CXX) $(OBJS) $(CXXFLAGS) $(TARGET) $(LIBS) -std=c++11

clean:
	rm  -f $(TARGET) core

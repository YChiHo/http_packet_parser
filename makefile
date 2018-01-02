C = gcc
CXX = g++
OBJS = http_parser.cpp
TARGET = parser
#LIBS = -ltins
HEADER = http_parser.h
CXXFLAGS=-g
.SUFFIXES : .cpp .o

all : $(TARGET)

$(TARGET) : $(OBJS)
        $(CXX) $(HEADER) $(OBJS) -o $(TARGET) $(LIBS)
#std = c++
#       $(CXX) $(OBJS) -o $(TARGET) $(LIBS) -std=c++11

clean:
        rm  -f $(TARGET) $(OBJS) core
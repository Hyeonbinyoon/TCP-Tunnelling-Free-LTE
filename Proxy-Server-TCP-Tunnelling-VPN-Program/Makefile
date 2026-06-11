CXX = g++
CXXFLAGS = -Wall -O2 -pthread
TARGET = proxy
OBJS = main.o proxy_control.o proxy_socket.o proxy_tun.o proxy_nat.o proxy_parser.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $(TARGET)

main.o: main.cpp proxy.h
	$(CXX) $(CXXFLAGS) -c main.cpp -o main.o

proxy_control.o: proxy_control.cpp proxy.h
	$(CXX) $(CXXFLAGS) -c proxy_control.cpp -o proxy_control.o

proxy_socket.o: proxy_socket.cpp proxy.h
	$(CXX) $(CXXFLAGS) -c proxy_socket.cpp -o proxy_socket.o

proxy_tun.o: proxy_tun.cpp proxy.h
	$(CXX) $(CXXFLAGS) -c proxy_tun.cpp -o proxy_tun.o

proxy_nat.o: proxy_nat.cpp proxy.h
	$(CXX) $(CXXFLAGS) -c proxy_nat.cpp -o proxy_nat.o

proxy_parser.o: proxy_parser.cpp proxy.h
	$(CXX) $(CXXFLAGS) -c proxy_parser.cpp -o proxy_parser.o

clean:
	rm -f $(TARGET) $(OBJS)

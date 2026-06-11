CXX = g++
CXXFLAGS = -Wall -O2 -pthread

TARGET = client
OBJS = main.o client_control.o client_tun.o client_socket.o client_parser.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $(TARGET)

%.o: %.cpp client.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)

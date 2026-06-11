CXX = g++
CXXFLAGS = -Wall -O2 -pthread
LDLIBS = -lnetfilter_queue

TARGET = proxy

OBJS = main.o \
       proxy_control.o \
       proxy_socket.o \
       proxy_tun.o \
       proxy_nat.o \
       proxy_parser.o \
       proxy_raw.o \
       proxy_nfqueue.o \
       proxy_udp.o \
       hb_headers.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.cpp proxy.h hb_headers.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
#include "client.h"

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

bool send_all(int fd, const uint8_t* data, size_t len)
{
    size_t sent = 0;

    while(sent < len)
    {
        ssize_t n = send(fd, data + sent, len - sent, 0);

        if(n > 0)
        {
            sent += static_cast<size_t>(n);
            continue;
        }

        if(n < 0 && errno == EINTR)
            continue;

        perror("send");
        return false;
    }

    return true;
}

bool set_tcp_mss(int sock, int mss)
{
    if(setsockopt(sock, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss)) < 0)
    {
        perror("setsockopt TCP_MAXSEG");
        return false;
    }

    return true;
}

int connect_proxy(const char* proxy_ip, uint16_t proxy_port)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0)
    {
        perror("socket");
        return -1;
    }

    if(!set_tcp_mss(sock, TCP_MSS))
    {
        close(sock);
        return -1;
    }

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(proxy_port);

    if(inet_pton(AF_INET, proxy_ip, &addr.sin_addr) != 1)
    {
        std::fprintf(stderr, "invalid proxy ip: %s\n", proxy_ip);
        close(sock);
        return -1;
    }

    if(connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        perror("connect");
        close(sock);
        return -1;
    }

    std::printf("connected to proxy %s:%u\n", proxy_ip, proxy_port);

    return sock;
}

void proxy_to_tun_loop(int proxy_fd, int tun_fd, std::atomic<bool>& stop)
{
    std::vector<uint8_t> stream_buffer;
    uint8_t buf[2048];

    while(!stop.load())
    {
        ssize_t n = recv(proxy_fd, buf, sizeof(buf), 0);
        if(n == 0)
        {
            std::fprintf(stderr, "[P->C] proxy disconnected\n");
            stop.store(true);
            break;
        }

        if(n < 0)
        {
            if(stop.load())
                break;

            if(errno == EINTR)
                continue;

            perror("recv proxy");
            stop.store(true);
            break;
        }

        std::printf("[P->C] recv %zd bytes from proxy\n", n);

        stream_buffer.insert(stream_buffer.end(), buf, buf + n);

        while(true)
        {
            std::vector<uint8_t> packet;
            if(!try_pop_ipv4_packet(stream_buffer, packet))
                break;

            print_ipv4_packet_info(packet);

            if(!write_packet_to_tun(tun_fd, packet))
            {
                stop.store(true);
                return;
            }
        }
    }
}

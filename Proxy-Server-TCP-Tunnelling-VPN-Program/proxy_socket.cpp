#include "proxy.h"

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <thread>
#include <chrono>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

int listen_tcp(uint16_t port)
{
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(listen_fd < 0)
    {
        perror("socket");
        return -1;
    }

    int opt = 1;
    if(setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("setsockopt SO_REUSEADDR");
        close(listen_fd);
        return -1;
    }

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if(bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        perror("bind");
        close(listen_fd);
        return -1;
    }

    if(listen(listen_fd, 1) < 0)
    {
        perror("listen");
        close(listen_fd);
        return -1;
    }

    std::printf("listening on 0.0.0.0:%u\n", port);
    return listen_fd;
}

int accept_client_with_signal(int listen_fd, sockaddr_in& peer)
{
    socklen_t peer_len = sizeof(peer);
    std::memset(&peer, 0, sizeof(peer));

    while(!g_signal_stop)
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(listen_fd, &rfds);

        timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(listen_fd + 1, &rfds, nullptr, nullptr, &tv);
        if(ret < 0)
        {
            if(errno == EINTR)
                continue;

            perror("select");
            return -1;
        }

        if(ret == 0)
            continue;

        if(FD_ISSET(listen_fd, &rfds))
        {
            int client_fd = accept(listen_fd, reinterpret_cast<sockaddr*>(&peer), &peer_len);
            if(client_fd < 0)
            {
                if(errno == EINTR && g_signal_stop)
                    return -1;

                perror("accept");
                return -1;
            }

            return client_fd;
        }
    }

    return -1;
}

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
        {
            if(g_signal_stop)
                return false;

            continue;
        }

        perror("send");
        return false;
    }

    return true;
}

void client_to_tun_loop(int client_fd, int tun_fd, std::atomic<bool>& stop)
{
    std::vector<uint8_t> stream_buffer;
    uint8_t buf[2048];

    while(!stop.load() && !g_signal_stop)
    {
        ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
        if(n == 0)
        {
            std::fprintf(stderr, "[C->P] client disconnected\n");
            stop.store(true);
            break;
        }

        if(n < 0)
        {
            if(stop.load() || g_signal_stop)
                break;

            if(errno == EINTR)
                continue;

            perror("[C->P] recv");
            stop.store(true);
            break;
        }

        std::printf("[C->P] recv %zd bytes from client\n", n);

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

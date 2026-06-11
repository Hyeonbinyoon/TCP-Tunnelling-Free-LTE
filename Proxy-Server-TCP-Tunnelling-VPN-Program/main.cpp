#include "proxy.h"

#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <chrono>
#include <unistd.h>
#include <arpa/inet.h>

static bool parse_port(const char* s, uint16_t& port)
{
    char* end = nullptr;
    errno = 0;

    long value = std::strtol(s, &end, 10);
    if(errno != 0 || end == s || *end != '\0' || value <= 0 || value > 65535)
    {
        std::fprintf(stderr, "invalid port: %s\n", s);
        return false;
    }

    port = static_cast<uint16_t>(value);
    return true;
}

int main(int argc, char* argv[])
{
    if(argc != 2)
    {
        std::fprintf(stderr, "syntax: %s <port>\n", argv[0]);
        return 1;
    }

    uint16_t listen_port;
    if(!parse_port(argv[1], listen_port))
        return 1;

    install_signal_handlers();

    int listen_fd = listen_tcp(listen_port);
    if(listen_fd < 0)
    {
        return 1;
    }

    sockaddr_in peer;
    int client_fd = accept_client_with_signal(listen_fd, peer);
    if(client_fd < 0)
    {
        std::printf("stopping proxy...\n");
        close(listen_fd);
        std::printf("proxy stopped cleanly\n");
        return 0;
    }

    char peer_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof(peer_ip));

    std::printf("accepted client: %s:%u\n", peer_ip, ntohs(peer.sin_port));

    int tun_fd = tun_alloc(PROXY_TUN_NAME);
    if(tun_fd < 0)
    {
        close(client_fd);
        close(listen_fd);
        return 1;
    }

    if(!set_nonblocking(tun_fd))
    {
        close(tun_fd);
        close(client_fd);
        close(listen_fd);
        return 1;
    }

    if(!setup_tun_interface(PROXY_TUN_NAME))
    {
        close(tun_fd);
        close(client_fd);
        close(listen_fd);
        return 1;
    }

    bool nat_rules_installed = false;

    if(!setup_nat_rules())
    {
        close(tun_fd);
        close(client_fd);
        close(listen_fd);
        return 1;
    }

    nat_rules_installed = true;

    std::atomic<bool> stop(false);

    std::thread client_thread(client_to_tun_loop, client_fd, tun_fd, std::ref(stop));
    std::thread tun_thread(tun_to_client_loop, tun_fd, client_fd, std::ref(stop));

    std::printf("proxy tunneling threads started\n");
    std::printf("press Ctrl+C to stop...\n");

    while(!g_signal_stop && !stop.load())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::printf("stopping proxy...\n");

    stop.store(true);

    shutdown(client_fd, SHUT_RDWR);

    if(client_thread.joinable())
        client_thread.join();

    if(tun_thread.joinable())
        tun_thread.join();

    if(nat_rules_installed)
    {
        cleanup_nat_rules();
    }

    close(tun_fd);
    close(client_fd);
    close(listen_fd);

    std::printf("proxy stopped cleanly\n");

    return 0;
}

#include "client.h"

#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <limits>
#include <thread>
#include <unistd.h>
#include <sys/socket.h>

static bool parse_port(const char* text, uint16_t& port)
{
    char* end = nullptr;
    errno = 0;
    unsigned long value = std::strtoul(text, &end, 10);

    if(errno != 0 || end == text || *end != '\0' || value == 0 || value > std::numeric_limits<uint16_t>::max())
    {
        return false;
    }

    port = static_cast<uint16_t>(value);
    return true;
}

int main(int argc, char* argv[])
{
    if(argc != 3)
    {
        std::fprintf(stderr, "syntax: %s <proxy-ip> <port>\n", argv[0]);
        return 1;
    }

    const char* proxy_ip = argv[1];

    uint16_t proxy_port;
    if(!parse_port(argv[2], proxy_port))
    {
        std::fprintf(stderr, "invalid port: %s\n", argv[2]);
        return 1;
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    int tun_fd = tun_alloc(CLIENT_TUN_NAME);
    if(tun_fd < 0)
    {
        return 1;
    }

    if(!set_nonblocking(tun_fd))
    {
        close(tun_fd);
        return 1;
    }

    if(!setup_tun_interface(CLIENT_TUN_NAME))
    {
        close(tun_fd);
        return 1;
    }

    RouteSnapshot route;
    if(!load_default_route(route))
    {
        close(tun_fd);
        return 1;
    }

    std::printf("default gateway: %s\n", route.gateway.c_str());
    std::printf("default ifname : %s\n", route.ifname.c_str());
    std::printf("default src    : %s\n", route.src.empty() ? "(none)" : route.src.c_str());

    std::string proxy_route = std::string(proxy_ip) + "/32";

    if(!add_route(route, proxy_route))
    {
        close(tun_fd);
        return 1;
}

    int proxy_fd = connect_proxy(proxy_ip, proxy_port);
    if(proxy_fd < 0)
    {
        cleanup_routes(route);
        close(tun_fd);
        return 1;
    }

    if(!replace_default_route_to_tun(route, CLIENT_TUN_NAME))
    {
        close(proxy_fd);
        cleanup_routes(route);
        close(tun_fd);
        return 1;
    }

    std::atomic<bool> stop(false);

    std::thread tun_thread(tun_to_proxy_loop, tun_fd, proxy_fd, std::ref(stop));
    std::thread proxy_thread(proxy_to_tun_loop, proxy_fd, tun_fd, std::ref(stop));

    std::printf("client tunneling threads started\n");
    std::printf("press Enter or Ctrl+C to stop...\n");

    wait_for_stop_request();

    std::printf("stopping client...\n");

    stop.store(true);

    /*
     * Important cleanup order:
     * 1. Restore default route while tunC still exists.
     * 2. Remove routes added by this program.
     * 3. Unblock socket recv thread.
     * 4. Join threads.
     * 5. Close fds.
     */
    restore_default_route(route);
    cleanup_routes(route);

    shutdown(proxy_fd, SHUT_RDWR);

    if(tun_thread.joinable())
        tun_thread.join();

    if(proxy_thread.joinable())
        proxy_thread.join();

    close(proxy_fd);
    close(tun_fd);

    std::printf("client stopped cleanly\n");

    return 0;
}

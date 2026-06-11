#ifndef CLIENT_H
#define CLIENT_H

#include <array>
#include <atomic>
#include <cstdint>
#include <csignal>
#include <string>
#include <vector>

#define CLIENT_TUN_NAME "tunC"
#define CLIENT_TUN_IP_CIDR "10.8.0.2/30"
#define TUN_MTU 1440
#define TCP_MSS 1400

extern volatile std::sig_atomic_t g_signal_stop;

struct RouteSnapshot
{
    std::string gateway;
    std::string ifname;
    std::string src;
    std::vector<std::string> added_routes;
    bool default_route_changed = false;
};

void handle_signal(int);
bool wait_for_stop_request();
bool run_cmd(const std::string& cmd);
bool add_route(RouteSnapshot& route, const std::string& cidr);
void cleanup_routes(const RouteSnapshot& route);
bool load_default_route(RouteSnapshot& route);
bool replace_default_route_to_tun(RouteSnapshot& route, const std::string& tun_name);
void restore_default_route(const RouteSnapshot& route);

bool set_nonblocking(int fd);
int tun_alloc(const char* dev_name);
bool setup_tun_interface(const char* dev_name);
bool write_packet_to_tun(int tun_fd, const std::vector<uint8_t>& packet);
void tun_to_proxy_loop(int tun_fd, int proxy_fd, std::atomic<bool>& stop);

bool send_all(int fd, const uint8_t* data, size_t len);
bool set_tcp_mss(int sock, int mss);
int connect_proxy(const char* proxy_ip, uint16_t proxy_port);
void proxy_to_tun_loop(int proxy_fd, int tun_fd, std::atomic<bool>& stop);

bool try_pop_ipv4_packet(std::vector<uint8_t>& buffer, std::vector<uint8_t>& packet);
void print_ipv4_packet_info(const std::vector<uint8_t>& packet);

#endif

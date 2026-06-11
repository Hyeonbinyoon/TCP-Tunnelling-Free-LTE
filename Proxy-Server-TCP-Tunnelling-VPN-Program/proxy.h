#ifndef PROXY_H
#define PROXY_H

#include <atomic>
#include <csignal>
#include <cstdint>
#include <string>
#include <vector>

#include <netinet/in.h>

#define PROXY_TUN_NAME "tunP0"
#define PROXY_TUN_IP_CIDR "10.8.0.1/30"
#define CLIENT_TUN_IP "10.8.0.2"
#define TUN_MTU 1440
#define PROXY_EXTERNAL_IFNAME "enp0s1"
#define SESSION_COMMENT "customvpn-session-1"

extern volatile std::sig_atomic_t g_signal_stop;

void install_signal_handlers();
bool set_nonblocking(int fd);
bool run_cmd(const std::string& cmd);

int listen_tcp(uint16_t port);
int accept_client_with_signal(int listen_fd, sockaddr_in& peer);
bool send_all(int fd, const uint8_t* data, size_t len);
void client_to_tun_loop(int client_fd, int tun_fd, std::atomic<bool>& stop);

int tun_alloc(const char* dev_name);
bool setup_tun_interface(const char* dev_name);
bool write_packet_to_tun(int tun_fd, const std::vector<uint8_t>& packet);
void tun_to_client_loop(int tun_fd, int client_fd, std::atomic<bool>& stop);

bool setup_nat_rules();
void cleanup_nat_rules();

bool try_pop_ipv4_packet(std::vector<uint8_t>& buffer, std::vector<uint8_t>& packet);
void print_ipv4_packet_info(const std::vector<uint8_t>& packet);

#endif // PROXY_H

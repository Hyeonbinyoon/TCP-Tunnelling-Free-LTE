#ifndef PROXY_H
#define PROXY_H

#include <atomic>
#include <csignal>
#include <cstdint>
#include <string>
#include <vector>
#include <mutex>

#include <netinet/in.h>

#define PROXY_TUN_NAME "tunP0"
#define PROXY_TUN_IP_CIDR "10.8.0.1/30"
#define CLIENT_TUN_IP "10.8.0.2"

////// for free LTE
#define TUN_MTU 1400
#define TCP_MSS 1360
#define OUTER_IP_TCP_HEADER_LEN 40
#define RAW_OUTER_MAX_LEN (TUN_MTU + OUTER_IP_TCP_HEADER_LEN)
#define RAW_TTL 64
#define PROXY_NFQUEUE_NUM 34
#define TCP_LEARN_MARKER 'L'
//////

#define PROXY_EXTERNAL_IFNAME "enp0s1"
#define SESSION_COMMENT "customvpn-session-1"


////// for free LTE
struct ProxyRawConfig
{
    uint32_t proxy_ip;
    uint32_t client_ip;
    uint16_t proxy_port;
    uint16_t client_port;
};

struct ProxyReadyState
{
    std::string client_nonce;
    std::string proxy_nonce;

    bool registered = false;
    bool client_ready_received = false;
    bool client_start_ack_received = false;
    bool ready_done = false;
    bool stop_received = false;

    sockaddr_in client_udp_addr;
    bool client_udp_addr_known = false;

    mutable std::mutex lock;
};

struct ProxyControlAckState
{
    uint32_t ip_src = 0;
    uint32_t ip_dst = 0;
    uint16_t tcp_src = 0;
    uint16_t tcp_dst = 0;
    uint32_t seq = 0;
    uint32_t ack = 0;
    uint8_t flags = 0;
    bool learned = false;
};

struct ProxyTunnelState
{
    std::atomic<int> tun_fd;
    std::atomic<bool> nfqueue_ready;
    std::atomic<bool> data_plane_ready;
    std::atomic<bool> session_stop;
    std::atomic<bool> session_error;

    ProxyControlAckState control_ack;

    ProxyTunnelState()
        : tun_fd(-1),
          nfqueue_ready(false),
          data_plane_ready(false),
          session_stop(false),
          session_error(false)
    {
    }
};

struct RealBase
{
    uint32_t client_seq = 0;
    uint32_t proxy_seq = 0;
    bool learned = false;
};

struct FakeBase
{
    uint32_t fake_client_seq = 0;
    uint32_t fake_proxy_seq = 0;
    bool initialized = false;
};

struct RawSendState
{
    uint64_t real_bytes_sent = 0;
    uint64_t fake_seq_offset = 0;
};
//////

extern volatile std::sig_atomic_t g_signal_stop;

void install_signal_handlers();
bool set_nonblocking(int fd);
bool run_cmd(const std::string& cmd);

int listen_tcp(uint16_t port);
int accept_client_with_signal(int listen_fd, sockaddr_in& peer);
bool send_all(int fd, const uint8_t* data, size_t len);
//void client_to_tun_loop(int client_fd, int tun_fd, std::atomic<bool>& stop);

int tun_alloc(const char* dev_name);
bool setup_tun_interface(const char* dev_name);
bool write_packet_to_tun(int tun_fd, const std::vector<uint8_t>& packet);
//void tun_to_client_loop(int tun_fd, int client_fd, std::atomic<bool>& stop);

bool setup_nat_rules();
void cleanup_nat_rules();

//bool try_pop_ipv4_packet(std::vector<uint8_t>& buffer, std::vector<uint8_t>& packet);
void print_ipv4_packet_info(const std::vector<uint8_t>& packet);





/////// for free LTE

// tcp/udp socket
int open_proxy_ready_socket(uint16_t ready_port);

// udp
bool run_proxy_udp_register(int udp_fd, ProxyReadyState& state, std::atomic<bool>& stop);
bool run_proxy_ready_handshake(int udp_fd, ProxyReadyState& state, std::atomic<bool>& stop);
bool send_proxy_learn_ready(int udp_fd, const ProxyReadyState& state);
void send_proxy_udp_stop(int udp_fd, const ProxyReadyState& state);
void proxy_udp_control_loop(int udp_fd, ProxyReadyState& state, ProxyTunnelState& tunnel_state, std::atomic<bool>& stop);

// raw socket
bool set_tcp_keepalive(int sock, int idle, int interval, int count);
bool init_proxy_raw_config(int client_fd, ProxyRawConfig& config);
int open_raw_send_socket();
void tun_to_raw_loop(int tun_fd, int raw_send_fd, const ProxyRawConfig& config, const FakeBase& fake_base, RawSendState& send_state, std::atomic<bool>& stop);

// learning
bool install_proxy_nfqueue_rule(const ProxyRawConfig& config, uint16_t queue_num);
void cleanup_proxy_nfqueue_rule(const ProxyRawConfig& config, uint16_t queue_num);
bool learn_proxy_tcp_base_with_nfqueue(uint16_t queue_num, int client_fd, int udp_fd, const ProxyRawConfig& config, const ProxyReadyState& ready_state, RealBase& real_base, FakeBase& fake_base, ProxyControlAckState& control_ack, std::atomic<bool>& stop);

// final nfqueue rule
bool install_proxy_tunnel_nfqueue_rule(const ProxyRawConfig& config, uint16_t queue_num);
void cleanup_proxy_tunnel_nfqueue_rule(const ProxyRawConfig& config, uint16_t queue_num);
void proxy_tunnel_nfqueue_loop(uint16_t queue_num, const ProxyRawConfig& config, ProxyTunnelState& tunnel_state, std::atomic<bool>& stop);

#endif // PROXY_H
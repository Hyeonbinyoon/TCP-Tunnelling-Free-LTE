#include "proxy.h"

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <sstream>
#include <string>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <mutex>

#define CLIENT_UDP_REGISTER_PREFIX "CUSTOMVPN_CLIENT_UDP_REGISTER_2024350225:"
#define PROXY_UDP_REGISTER_ACK_PREFIX "CUSTOMVPN_PROXY_UDP_REGISTER_ACK_2024350225:"
#define PROXY_LEARN_READY_PREFIX "CUSTOMVPN_PROXY_LEARN_READY_2024350225:"
#define CLIENT_TUNNEL_READY_PREFIX "CUSTOMVPN_CLIENT_TUNNEL_READY_2024350225:"
#define PROXY_TUNNEL_READY_ACK_PREFIX "CUSTOMVPN_PROXY_TUNNEL_READY_ACK_2024350225:"
#define CLIENT_START_ACK_PREFIX "CUSTOMVPN_CLIENT_START_ACK_2024350225:"
#define UDP_STOP_PREFIX "CUSTOMVPN_UDP_STOP_2024350225:"

#define UDP_RETRY_INTERVAL_MS 500
#define UDP_TIMEOUT_SECONDS 20
#define UDP_STOP_REPEAT_COUNT 5
#define UDP_STOP_INTERVAL_MS 100
#define UDP_BUFFER_SIZE 512


static std::string make_proxy_nonce()
{
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    std::ostringstream oss;
    oss << "proxy_" << getpid() << "_" << ts.tv_sec << "_" << ts.tv_nsec;

    return oss.str();
}


// UDP marker 송신
static bool udp_send_string(int udp_fd, const sockaddr_in& addr, const std::string& msg)
{
    ssize_t n = sendto(udp_fd, msg.data(), msg.size(), 0, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
    if(n < 0)
    {
        perror("sendto UDP");
        return false;
    }

    if(static_cast<size_t>(n) != msg.size())
    {
        std::fprintf(stderr, "partial UDP send\n");
        return false;
    }

    return true;
}


// timeout 기반 UDP marker 수신
static bool udp_recv_string(int udp_fd, std::string& msg, sockaddr_in& sender_addr, int timeout_ms)
{
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(udp_fd, &rfds);

    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int ret = select(udp_fd + 1, &rfds, nullptr, nullptr, &tv);
    if(ret == 0)
        return false;

    if(ret < 0)
    {
        if(errno == EINTR)
            return false;

        perror("select UDP");
        return false;
    }

    char buf[UDP_BUFFER_SIZE];

    socklen_t sender_len = sizeof(sender_addr);
    std::memset(&sender_addr, 0, sizeof(sender_addr));

    ssize_t n = recvfrom(udp_fd, buf, sizeof(buf) - 1, 0, reinterpret_cast<sockaddr*>(&sender_addr), &sender_len);
    if(n < 0)
    {
        if(errno == EINTR)
            return false;

        perror("recvfrom UDP");
        return false;
    }

    buf[n] = '\0';
    msg.assign(buf, static_cast<size_t>(n));

    return true;
}


// marker prefix 확인
static bool starts_with(const std::string& s, const char* prefix)
{
    size_t prefix_len = std::strlen(prefix);

    if(s.size() < prefix_len)
        return false;

    return s.compare(0, prefix_len, prefix) == 0;
}


// UDP_TIMEOUT_SECONDS 계산
static uint64_t now_ms()
{
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return static_cast<uint64_t>(ts.tv_sec) * 1000ULL + static_cast<uint64_t>(ts.tv_nsec) / 1000000ULL;
}


static bool parse_client_register(const std::string& msg, std::string& client_nonce)
{
    if(!starts_with(msg, CLIENT_UDP_REGISTER_PREFIX))
        return false;

    client_nonce = msg.substr(std::strlen(CLIENT_UDP_REGISTER_PREFIX));

    return !client_nonce.empty();
}


static bool is_valid_client_ready(const std::string& msg, const ProxyReadyState& state)
{
    std::string client_nonce;

    {
        std::lock_guard<std::mutex> guard(state.lock);
        client_nonce = state.client_nonce;
    }

    if(client_nonce.empty())
        return false;

    std::string expected = std::string(CLIENT_TUNNEL_READY_PREFIX) + client_nonce;

    return msg == expected;
}


static bool is_valid_client_start_ack(const std::string& msg, const ProxyReadyState& state)
{
    std::string proxy_nonce;

    {
        std::lock_guard<std::mutex> guard(state.lock);
        proxy_nonce = state.proxy_nonce;
    }

    if(proxy_nonce.empty())
        return false;

    std::string expected = std::string(CLIENT_START_ACK_PREFIX) + proxy_nonce;

    return msg == expected;
}


static bool is_valid_udp_stop(const std::string& msg, const ProxyReadyState& state)
{
    std::string client_nonce;
    std::string proxy_nonce;

    {
        std::lock_guard<std::mutex> guard(state.lock);
        client_nonce = state.client_nonce;
        proxy_nonce = state.proxy_nonce;
    }

    if(client_nonce.empty() || proxy_nonce.empty())
        return false;

    std::string expected = std::string(UDP_STOP_PREFIX) + client_nonce + ":" + proxy_nonce;

    return msg == expected;
}


static bool send_proxy_register_ack(int udp_fd, const sockaddr_in& client_addr, const std::string& client_nonce, const std::string& proxy_nonce)
{
    std::string ack_msg = std::string(PROXY_UDP_REGISTER_ACK_PREFIX) + client_nonce + ":" + proxy_nonce;

    return udp_send_string(udp_fd, client_addr, ack_msg);
}

bool send_proxy_learn_ready(int udp_fd, const ProxyReadyState& state)
{
    if(udp_fd < 0)
    {
        std::fprintf(stderr, "[UDP LEARN] invalid udp fd\n");
        return false;
    }

    std::string client_nonce;
    std::string proxy_nonce;
    sockaddr_in client_addr;
    bool registered = false;
    bool client_udp_addr_known = false;

    {
        std::lock_guard<std::mutex> guard(state.lock);

        client_nonce = state.client_nonce;
        proxy_nonce = state.proxy_nonce;
        client_addr = state.client_udp_addr;
        registered = state.registered;
        client_udp_addr_known = state.client_udp_addr_known;
    }

    if(!registered || client_nonce.empty() || proxy_nonce.empty() || !client_udp_addr_known)
    {
        std::fprintf(stderr, "[UDP LEARN] UDP register is not completed\n");
        return false;
    }

    std::string learn_ready_msg =
        std::string(PROXY_LEARN_READY_PREFIX) + client_nonce + ":" + proxy_nonce;

    if(!udp_send_string(udp_fd, client_addr, learn_ready_msg))
        return false;

    std::printf("[UDP LEARN] sent PROXY_LEARN_READY\n");

    return true;
}

int open_proxy_ready_socket(uint16_t ready_port)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0)
    {
        perror("socket UDP ready");
        return -1;
    }

    int opt = 1;
    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("setsockopt UDP SO_REUSEADDR");
        close(sock);
        return -1;
    }

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(ready_port);

    if(bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        perror("bind UDP ready");
        close(sock);
        return -1;
    }

    std::printf("[UDP] ready socket bound on 0.0.0.0:%u\n", ready_port);

    return sock;
}


// Client UDP endpoint를 등록하고, Client에게 Proxy nonce를 전달
bool run_proxy_udp_register(int udp_fd, ProxyReadyState& state, std::atomic<bool>& stop)
{
    if(udp_fd < 0)
    {
        std::fprintf(stderr, "[UDP REGISTER] invalid udp fd\n");
        return false;
    }

    {
        std::lock_guard<std::mutex> guard(state.lock);

        if(state.proxy_nonce.empty())
            state.proxy_nonce = make_proxy_nonce();
    }

    uint64_t start_time = now_ms();

    std::printf("[UDP REGISTER] start\n");

    while(!g_signal_stop && !stop.load())
    {
        uint64_t current_time = now_ms();

        if(current_time - start_time >= UDP_TIMEOUT_SECONDS * 1000ULL)
        {
            std::fprintf(stderr, "[UDP REGISTER] timeout\n");
            return false;
        }

        std::string recv_msg;
        sockaddr_in sender_addr;

        if(!udp_recv_string(udp_fd, recv_msg, sender_addr, UDP_RETRY_INTERVAL_MS))
            continue;

        std::string client_nonce;
        if(!parse_client_register(recv_msg, client_nonce))
        {
            std::printf("[UDP REGISTER] ignore unexpected UDP message: %s\n", recv_msg.c_str());
            continue;
        }

        std::string proxy_nonce;

        {
            std::lock_guard<std::mutex> guard(state.lock);

            state.client_nonce = client_nonce;
            state.client_udp_addr = sender_addr;
            state.client_udp_addr_known = true;
            state.registered = true;

            proxy_nonce = state.proxy_nonce;
        }

        if(!send_proxy_register_ack(udp_fd, sender_addr, client_nonce, proxy_nonce))
            return false;

        std::printf("[UDP REGISTER] received CLIENT_REGISTER\n");
        std::printf("[UDP REGISTER] client_nonce=%s\n", client_nonce.c_str());
        std::printf("[UDP REGISTER] proxy_nonce=%s\n", proxy_nonce.c_str());
        std::printf("[UDP REGISTER] sent REGISTER_ACK\n");
        std::printf("[UDP REGISTER] done\n");

        return true;
    }

    return false;
}


// 양쪽 tunnel NFQUEUE가 준비됐는지 확인하고, data plane 시작 OK 맞춤
bool run_proxy_ready_handshake(int udp_fd, ProxyReadyState& state, std::atomic<bool>& stop)
{
    if(udp_fd < 0)
    {
        std::fprintf(stderr, "[UDP READY] invalid udp fd\n");
        return false;
    }

    std::string client_nonce;
    std::string proxy_nonce;
    sockaddr_in client_addr;

    {
        std::lock_guard<std::mutex> guard(state.lock);

        if(!state.registered || state.client_nonce.empty() || state.proxy_nonce.empty() || !state.client_udp_addr_known)
        {
            std::fprintf(stderr, "[UDP READY] UDP register is not completed\n");
            return false;
        }

        client_nonce = state.client_nonce;
        proxy_nonce = state.proxy_nonce;
        client_addr = state.client_udp_addr;
    }

    std::string ready_ack_msg = std::string(PROXY_TUNNEL_READY_ACK_PREFIX) + client_nonce + ":" + proxy_nonce;

    uint64_t start_time = now_ms();
    uint64_t next_send_time = 0;

    std::printf("[UDP READY] start\n");

    while(!g_signal_stop && !stop.load())
    {
        bool client_ready_received = false;
        bool client_start_ack_received = false;
        bool stop_received = false;

        {
            std::lock_guard<std::mutex> guard(state.lock);
            client_ready_received = state.client_ready_received;
            client_start_ack_received = state.client_start_ack_received;
            stop_received = state.stop_received;
        }

        if(stop_received)
        {
            std::fprintf(stderr, "[UDP READY] stop received while waiting START_ACK\n");
            return false;
        }

        if(client_start_ack_received)
        {
            {
                std::lock_guard<std::mutex> guard(state.lock);
                state.ready_done = true;
            }

            std::printf("[UDP READY] done\n");
            return true;
        }

        uint64_t current_time = now_ms();

        if(current_time - start_time >= UDP_TIMEOUT_SECONDS * 1000ULL)
        {
            std::fprintf(stderr, "[UDP READY] timeout\n");
            return false;
        }

        if(client_ready_received && current_time >= next_send_time)
        {
            if(!udp_send_string(udp_fd, client_addr, ready_ack_msg))
                return false;

            std::printf("[UDP READY] sent PROXY_READY_ACK\n");

            next_send_time = current_time + UDP_RETRY_INTERVAL_MS;
        }

        usleep(10 * 1000);
    }

    return false;
}


// Ctrl+C 또는 local cleanup 시 Client에게 종료 신호를 보냄
void send_proxy_udp_stop(int udp_fd, const ProxyReadyState& state)
{
    if(udp_fd < 0)
    {
        std::fprintf(stderr, "[UDP STOP] invalid udp fd\n");
        return;
    }

    std::string client_nonce;
    std::string proxy_nonce;
    sockaddr_in client_addr;
    bool client_udp_addr_known = false;

    {
        std::lock_guard<std::mutex> guard(state.lock);

        client_nonce = state.client_nonce;
        proxy_nonce = state.proxy_nonce;
        client_addr = state.client_udp_addr;
        client_udp_addr_known = state.client_udp_addr_known;
    }

    if(client_nonce.empty() || proxy_nonce.empty() || !client_udp_addr_known)
    {
        std::fprintf(stderr, "[UDP STOP] nonce or client UDP addr is not ready. skip UDP STOP\n");
        return;
    }

    std::string stop_msg = std::string(UDP_STOP_PREFIX) + client_nonce + ":" + proxy_nonce;

    for(int i = 0; i < UDP_STOP_REPEAT_COUNT; ++i)
    {
        if(!udp_send_string(udp_fd, client_addr, stop_msg))
        {
            std::fprintf(stderr, "[UDP STOP] failed to send UDP STOP\n");
            return;
        }

        std::printf("[UDP STOP] sent UDP STOP\n");
        usleep(UDP_STOP_INTERVAL_MS * 1000);
    }
}


void proxy_udp_control_loop(int udp_fd, ProxyReadyState& state, ProxyTunnelState& tunnel_state, std::atomic<bool>& stop)
{
    while(!g_signal_stop && !stop.load() && !tunnel_state.session_stop.load() && !tunnel_state.session_error.load())
    {
        std::string recv_msg;
        sockaddr_in sender_addr;

        if(!udp_recv_string(udp_fd, recv_msg, sender_addr, UDP_RETRY_INTERVAL_MS))
            continue;

        if(starts_with(recv_msg, UDP_STOP_PREFIX))
        {
            if(!is_valid_udp_stop(recv_msg, state))
            {
                std::printf("[UDP CONTROL] ignore UDP STOP with wrong nonce: %s\n", recv_msg.c_str());
                continue;
            }

            {
                std::lock_guard<std::mutex> guard(state.lock);
                state.stop_received = true;
            }

            std::fprintf(stderr, "[UDP CONTROL] received valid UDP STOP\n");
            tunnel_state.session_stop.store(true);
            stop.store(true);
            return;
        }

        if(starts_with(recv_msg, CLIENT_UDP_REGISTER_PREFIX))
        {
            std::string client_nonce;
            if(!parse_client_register(recv_msg, client_nonce))
            {
                std::printf("[UDP CONTROL] ignore invalid CLIENT_REGISTER: %s\n", recv_msg.c_str());
                continue;
            }

            std::string current_client_nonce;
            std::string proxy_nonce;

            {
                std::lock_guard<std::mutex> guard(state.lock);
                current_client_nonce = state.client_nonce;
                proxy_nonce = state.proxy_nonce;
            }

            if(client_nonce != current_client_nonce)
            {
                std::printf("[UDP CONTROL] ignore CLIENT_REGISTER with wrong nonce: %s\n", recv_msg.c_str());
                continue;
            }

            if(!send_proxy_register_ack(udp_fd, sender_addr, client_nonce, proxy_nonce))
            {
                tunnel_state.session_error.store(true);
                stop.store(true);
                return;
            }

            std::printf("[UDP CONTROL] resent REGISTER_ACK\n");
            continue;
        }

        if(starts_with(recv_msg, CLIENT_TUNNEL_READY_PREFIX))
        {
            if(!is_valid_client_ready(recv_msg, state))
            {
                std::printf("[UDP CONTROL] ignore CLIENT_READY with wrong nonce: %s\n", recv_msg.c_str());
                continue;
            }

            bool first_ready = false;

            {
                std::lock_guard<std::mutex> guard(state.lock);

                if(!state.client_ready_received)
                    first_ready = true;

                state.client_ready_received = true;
                state.client_udp_addr = sender_addr;
                state.client_udp_addr_known = true;
            }

            if(first_ready)
                std::printf("[UDP CONTROL] received valid CLIENT_READY\n");

            continue;
        }

        if(starts_with(recv_msg, CLIENT_START_ACK_PREFIX))
        {
            if(!is_valid_client_start_ack(recv_msg, state))
            {
                std::printf("[UDP CONTROL] ignore CLIENT_START_ACK with wrong nonce: %s\n", recv_msg.c_str());
                continue;
            }

            bool first_start_ack = false;

            {
                std::lock_guard<std::mutex> guard(state.lock);

                if(!state.client_start_ack_received)
                    first_start_ack = true;

                state.client_start_ack_received = true;
            }

            if(first_start_ack)
                std::printf("[UDP CONTROL] received valid CLIENT_START_ACK\n");

            continue;
        }

        std::printf("[UDP CONTROL] ignore unexpected UDP message: %s\n", recv_msg.c_str());
    }
}
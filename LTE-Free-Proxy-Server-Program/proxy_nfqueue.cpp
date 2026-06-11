// for free LTE
#include "proxy.h"
#include "hb_headers.h"

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <string>
#include <vector>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

static constexpr uint8_t TCP_FLAG_FIN = 0x01;
static constexpr uint8_t TCP_FLAG_SYN = 0x02;
static constexpr uint8_t TCP_FLAG_RST = 0x04;
static constexpr uint8_t TCP_FLAG_ACK = 0x10;

struct ParsedOuterTcpPacket
{
    const hb_ip_hdr* ip = nullptr;
    const hb_tcp_hdr* tcp = nullptr;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
    uint32_t seq = 0;
    uint32_t ack = 0;
};

struct ProxyNfqueueContext
{
    const ProxyRawConfig* config = nullptr;
    RealBase* real_base = nullptr;
    FakeBase* fake_base = nullptr;
    ProxyControlAckState* control_ack = nullptr;
    bool learned = false;
};

struct ProxyTunnelNfqueueContext
{
    const ProxyRawConfig* config = nullptr;
    ProxyTunnelState* tunnel_state = nullptr;
};

static uint32_t get_packet_id(nfq_data* nfad)
{
    nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfad);
    if(ph == nullptr)
        return 0;

    return ntohl(ph->packet_id);
}

static bool ip_to_string(uint32_t ip_net, std::string& out)
{
    char buf[INET_ADDRSTRLEN];

    if(inet_ntop(AF_INET, &ip_net, buf, sizeof(buf)) == nullptr)
        return false;

    out = buf;
    return true;
}

static bool parse_client_to_proxy_tcp_packet(
    const uint8_t* packet,
    size_t packet_len,
    const ProxyRawConfig& config,
    ParsedOuterTcpPacket& parsed)
{
    if(packet == nullptr)
        return false;

    if(packet_len < HB_IPV4_H_SIZE)
        return false;

    const hb_ip_hdr* ip = reinterpret_cast<const hb_ip_hdr*>(packet);

    if(ip->version() != IP_VERSION_IPv4)
        return false;

    if(ip->protocol_value() != IP_PROTOCOL_TCP)
        return false;

    size_t ip_header_len = ip->header_len();
    if(ip_header_len < HB_IPV4_H_SIZE)
        return false;

    if(packet_len < ip_header_len + HB_TCP_H_SIZE)
        return false;

    uint16_t ip_total_len = ip->total_length();
    if(ip_total_len < ip_header_len + HB_TCP_H_SIZE)
        return false;

    if(packet_len < ip_total_len)
        return false;

    if(ip->src_ip != config.client_ip)
        return false;

    if(ip->dst_ip != config.proxy_ip)
        return false;

    const hb_tcp_hdr* tcp = reinterpret_cast<const hb_tcp_hdr*>(packet + ip_header_len);

    size_t tcp_header_len = tcp->header_len();
    if(tcp_header_len < HB_TCP_H_SIZE)
        return false;

    if(ip_total_len < ip_header_len + tcp_header_len)
        return false;

    if(tcp->src_port_value() != config.client_port)
        return false;

    if(tcp->dst_port_value() != config.proxy_port)
        return false;

    size_t payload_offset = ip_header_len + tcp_header_len;
    size_t payload_len = ip_total_len - payload_offset;

    parsed.ip = ip;
    parsed.tcp = tcp;
    parsed.payload = packet + payload_offset;
    parsed.payload_len = payload_len;
    parsed.seq = ntohl(tcp->seq_num);
    parsed.ack = ntohl(tcp->ack_num);

    return true;
}

static bool is_proxy_learning_marker_packet(const ParsedOuterTcpPacket& parsed)
{
    if(parsed.payload == nullptr)
        return false;

    if(parsed.payload_len != 1)
        return false;

    if(parsed.payload[0] != static_cast<uint8_t>(TCP_LEARN_MARKER))
        return false;

    return true;
}

static bool consume_tcp_learn_marker(int client_fd, std::atomic<bool>& stop)
{
    if(client_fd < 0)
    {
        std::fprintf(stderr, "[NFQ P-LEARN] invalid client fd for marker consume\n");
        return false;
    }

    uint64_t waited_ms = 0;

    while(!stop.load() && !g_signal_stop && waited_ms < 3000)
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(client_fd, &rfds);

        timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100 * 1000;

        int ret = select(client_fd + 1, &rfds, nullptr, nullptr, &tv);
        if(ret < 0)
        {
            if(errno == EINTR)
                continue;

            perror("[NFQ P-LEARN] select client fd");
            return false;
        }

        if(ret == 0)
        {
            waited_ms += 100;
            continue;
        }

        uint8_t marker = 0;
        ssize_t n = recv(client_fd, &marker, 1, MSG_WAITALL);
        if(n < 0)
        {
            if(errno == EINTR)
                continue;

            perror("[NFQ P-LEARN] recv TCP learn marker");
            return false;
        }

        if(n == 0)
        {
            std::fprintf(stderr, "[NFQ P-LEARN] TCP connection closed while consuming marker\n");
            return false;
        }

        if(marker != static_cast<uint8_t>(TCP_LEARN_MARKER))
        {
            std::fprintf(stderr,
                         "[NFQ P-LEARN] unexpected TCP marker byte: 0x%02x\n",
                         marker);
            return false;
        }

        std::printf("[NFQ P-LEARN] consumed TCP learn marker from control socket\n");
        return true;
    }

    std::fprintf(stderr, "[NFQ P-LEARN] timeout while consuming TCP learn marker\n");
    return false;
}

static int proxy_learning_callback(nfq_q_handle* qh, nfgenmsg*, nfq_data* nfad, void* data)
{
    ProxyNfqueueContext* ctx = reinterpret_cast<ProxyNfqueueContext*>(data);
    uint32_t packet_id = get_packet_id(nfad);

    unsigned char* raw_payload = nullptr;
    int payload_len = nfq_get_payload(nfad, &raw_payload);

    if(payload_len < 0)
    {
        std::fprintf(stderr, "[NFQ P-LEARN] failed to get payload\n");
        return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, nullptr);
    }

    ParsedOuterTcpPacket parsed;
    if(!parse_client_to_proxy_tcp_packet(raw_payload,
                                         static_cast<size_t>(payload_len),
                                         *ctx->config,
                                         parsed))
    {
        std::fprintf(stderr, "[NFQ P-LEARN] accept non-target or invalid packet\n");
        return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, nullptr);
    }

    std::printf("[NFQ P-LEARN] tcp packet seq=%u ack=%u flags=0x%02x payload_len=%zu\n",
                parsed.seq,
                parsed.ack,
                parsed.tcp->flags,
                parsed.payload_len);

    if(!is_proxy_learning_marker_packet(parsed))
    {
        std::printf("[NFQ P-LEARN] accept non-marker packet\n");
        return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, nullptr);
    }

    ctx->real_base->client_seq = parsed.seq;
    ctx->real_base->proxy_seq = parsed.ack - 1;
    ctx->real_base->learned = true;

    ctx->fake_base->fake_client_seq = parsed.seq + 1;
    ctx->fake_base->fake_proxy_seq = parsed.ack;
    ctx->fake_base->initialized = true;

    ctx->control_ack->ip_src = parsed.ip->src_ip;
    ctx->control_ack->ip_dst = parsed.ip->dst_ip;
    ctx->control_ack->tcp_src = parsed.tcp->src_port_value();
    ctx->control_ack->tcp_dst = parsed.tcp->dst_port_value();
    ctx->control_ack->seq = ctx->fake_base->fake_client_seq;
    ctx->control_ack->ack = ctx->fake_base->fake_proxy_seq;
    ctx->control_ack->flags = TCP_FLAG_ACK;
    ctx->control_ack->learned = true;

    ctx->learned = true;

    std::printf("[NFQ P-LEARN] learned realBase from TCP learn marker\n");

    std::printf("[NFQ P-LEARN] realBase: client_seq=%u proxy_seq=%u\n",
                ctx->real_base->client_seq,
                ctx->real_base->proxy_seq);

    std::printf("[NFQ P-LEARN] fakeBase: fake_client_seq=%u fake_proxy_seq=%u\n",
                ctx->fake_base->fake_client_seq,
                ctx->fake_base->fake_proxy_seq);

    std::printf("[NFQ P-LEARN] control ACK state: seq=%u ack=%u flags=0x%02x\n",
                ctx->control_ack->seq,
                ctx->control_ack->ack,
                ctx->control_ack->flags);

    return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, nullptr);
}

static bool is_proxy_allowed_control_ack(const ParsedOuterTcpPacket& parsed, const ProxyControlAckState& learned)
{
    if(!learned.learned)
        return false;

    if(parsed.ip == nullptr || parsed.tcp == nullptr)
        return false;

    if(parsed.payload_len != 0)
        return false;

    if(parsed.tcp->flags != TCP_FLAG_ACK)
        return false;

    if(parsed.ip->src_ip != learned.ip_src)
        return false;

    if(parsed.ip->dst_ip != learned.ip_dst)
        return false;

    if(parsed.tcp->src_port_value() != learned.tcp_src)
        return false;

    if(parsed.tcp->dst_port_value() != learned.tcp_dst)
        return false;

    if(parsed.ack != learned.ack)
        return false;

    uint32_t client_normal_ack_seq = learned.seq;
    uint32_t client_keepalive_probe_seq = learned.seq - 1;

    if(parsed.seq != client_normal_ack_seq && parsed.seq != client_keepalive_probe_seq)
        return false;

    return true;
}

static bool extract_inner_ipv4_packet(const uint8_t* payload, size_t payload_len, std::vector<uint8_t>& inner_packet)
{
    if(payload == nullptr)
        return false;

    if(payload_len < HB_IPV4_H_SIZE)
        return false;

    const hb_ip_hdr* inner_ip = reinterpret_cast<const hb_ip_hdr*>(payload);

    if(inner_ip->version() != IP_VERSION_IPv4)
        return false;

    size_t inner_ip_header_len = inner_ip->header_len();
    if(inner_ip_header_len < HB_IPV4_H_SIZE)
        return false;

    if(payload_len < inner_ip_header_len)
        return false;

    uint16_t inner_total_len = inner_ip->total_length();
    if(inner_total_len < inner_ip_header_len)
        return false;

    if(inner_total_len != payload_len)
        return false;

    if(inner_total_len > TUN_MTU)
        return false;

    inner_packet.assign(payload, payload + inner_total_len);
    return true;
}

static int proxy_tunnel_callback(nfq_q_handle* qh, nfgenmsg*, nfq_data* nfad, void* data)
{
    ProxyTunnelNfqueueContext* ctx = reinterpret_cast<ProxyTunnelNfqueueContext*>(data);
    uint32_t packet_id = get_packet_id(nfad);

    unsigned char* raw_payload = nullptr;
    int payload_len = nfq_get_payload(nfad, &raw_payload);

    if(payload_len < 0)
    {
        std::fprintf(stderr, "[NFQ P-TUNNEL] failed to get payload\n");
        return nfq_set_verdict(qh, packet_id, NF_DROP, 0, nullptr);
    }

    ParsedOuterTcpPacket parsed;
    if(!parse_client_to_proxy_tcp_packet(raw_payload, static_cast<size_t>(payload_len), *ctx->config, parsed))
    {
        std::fprintf(stderr, "[NFQ P-TUNNEL] drop unparsed packet\n");
        return nfq_set_verdict(qh, packet_id, NF_DROP, 0, nullptr);
    }

    if(parsed.payload_len == 0)
    {
        if(is_proxy_allowed_control_ack(parsed, ctx->tunnel_state->control_ack))
        {
            return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, nullptr);
        }

        std::fprintf(stderr,
                     "[NFQ P-TUNNEL] drop non-allowed control packet seq=%u ack=%u flags=0x%02x\n",
                     parsed.seq,
                     parsed.ack,
                     parsed.tcp->flags);

        return nfq_set_verdict(qh, packet_id, NF_DROP, 0, nullptr);
    }

    if(!ctx->tunnel_state->data_plane_ready.load())
    {
        std::fprintf(stderr, "[NFQ P-TUNNEL] drop payload before data plane ready payload_len=%zu\n", parsed.payload_len);
        return nfq_set_verdict(qh, packet_id, NF_DROP, 0, nullptr);
    }

    std::vector<uint8_t> inner_packet;
    if(!extract_inner_ipv4_packet(parsed.payload, parsed.payload_len, inner_packet))
    {
        std::fprintf(stderr, "[NFQ P-TUNNEL] drop invalid inner IPv4 payload_len=%zu\n", parsed.payload_len);
        return nfq_set_verdict(qh, packet_id, NF_DROP, 0, nullptr);
    }

    int tun_fd = ctx->tunnel_state->tun_fd.load();
    if(tun_fd < 0)
    {
        std::fprintf(stderr, "[NFQ P-TUNNEL] tun fd is not ready\n");
        return nfq_set_verdict(qh, packet_id, NF_DROP, 0, nullptr);
    }

    if(!write_packet_to_tun(tun_fd, inner_packet))
    {
        std::fprintf(stderr, "[NFQ P-TUNNEL] failed to write inner packet to tun\n");
        ctx->tunnel_state->session_error.store(true);
        return nfq_set_verdict(qh, packet_id, NF_DROP, 0, nullptr);
    }

    std::printf("[NFQ P-TUNNEL] wrote inner IPv4 packet to tun len=%zu\n", inner_packet.size());
    return nfq_set_verdict(qh, packet_id, NF_DROP, 0, nullptr);
}

bool install_proxy_nfqueue_rule(const ProxyRawConfig& config, uint16_t queue_num)
{
    std::string proxy_ip;
    std::string client_ip;

    if(!ip_to_string(config.proxy_ip, proxy_ip))
    {
        std::fprintf(stderr, "failed to convert proxy ip\n");
        return false;
    }

    if(!ip_to_string(config.client_ip, client_ip))
    {
        std::fprintf(stderr, "failed to convert client ip\n");
        return false;
    }

    std::string cmd =
        "iptables -I INPUT "
        "-p tcp "
        "-s " + client_ip + " "
        "--sport " + std::to_string(config.client_port) + " "
        "-d " + proxy_ip + " "
        "--dport " + std::to_string(config.proxy_port) + " "
        "-j NFQUEUE --queue-num " + std::to_string(queue_num);

    return run_cmd(cmd);
}

void cleanup_proxy_nfqueue_rule(const ProxyRawConfig& config, uint16_t queue_num)
{
    std::string proxy_ip;
    std::string client_ip;

    if(!ip_to_string(config.proxy_ip, proxy_ip))
        return;

    if(!ip_to_string(config.client_ip, client_ip))
        return;

    std::string cmd =
        "iptables -D INPUT "
        "-p tcp "
        "-s " + client_ip + " "
        "--sport " + std::to_string(config.client_port) + " "
        "-d " + proxy_ip + " "
        "--dport " + std::to_string(config.proxy_port) + " "
        "-j NFQUEUE --queue-num " + std::to_string(queue_num) +
        " 2>/dev/null";

    run_cmd(cmd);
}

bool learn_proxy_tcp_base_with_nfqueue(uint16_t queue_num, int client_fd, int udp_fd, const ProxyRawConfig& config, const ProxyReadyState& ready_state, RealBase& real_base, FakeBase& fake_base, ProxyControlAckState& control_ack, std::atomic<bool>& stop)
{
    nfq_handle* h = nfq_open();
    if(h == nullptr)
    {
        std::fprintf(stderr, "nfq_open failed\n");
        return false;
    }

    if(nfq_unbind_pf(h, AF_INET) < 0)
    {
        std::fprintf(stderr, "nfq_unbind_pf(AF_INET) failed\n");
        nfq_close(h);
        return false;
    }

    if(nfq_bind_pf(h, AF_INET) < 0)
    {
        std::fprintf(stderr, "nfq_bind_pf(AF_INET) failed\n");
        nfq_close(h);
        return false;
    }

    ProxyNfqueueContext ctx;
    ctx.config = &config;
    ctx.real_base = &real_base;
    ctx.fake_base = &fake_base;
    ctx.control_ack = &control_ack;
    ctx.learned = false;

    nfq_q_handle* qh = nfq_create_queue(h, queue_num, &proxy_learning_callback, &ctx);
    if(qh == nullptr)
    {
        std::fprintf(stderr, "nfq_create_queue failed\n");
        nfq_close(h);
        return false;
    }

    if(nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        std::fprintf(stderr, "nfq_set_mode failed\n");
        nfq_destroy_queue(qh);
        nfq_close(h);
        return false;
    }

    if(!send_proxy_learn_ready(udp_fd, ready_state))
    {
        std::fprintf(stderr, "[NFQ P-LEARN] failed to send PROXY_LEARN_READY\n");
        nfq_destroy_queue(qh);
        nfq_close(h);
        return false;
    }

    int fd = nfq_fd(h);
    char buf[4096];

    std::printf("[NFQ P-LEARN] waiting for Client -> Proxy TCP learn marker on queue %u...\n", queue_num);

    while(!stop.load() && !g_signal_stop && !ctx.learned)
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(fd + 1, &rfds, nullptr, nullptr, &tv);
        if(ret < 0)
        {
            if(errno == EINTR)
                continue;

            perror("[NFQ P-LEARN] select");
            break;
        }

        if(ret == 0)
            continue;

        ssize_t rv = recv(fd, buf, sizeof(buf), 0);
        if(rv < 0)
        {
            if(errno == EINTR)
                continue;

            perror("[NFQ P-LEARN] recv");
            break;
        }

        nfq_handle_packet(h, buf, static_cast<int>(rv));
    }

    bool learned = ctx.learned;

    if(!learned)
    {
        nfq_destroy_queue(qh);
        nfq_close(h);

        std::fprintf(stderr, "[NFQ P-LEARN] learning failed or stopped\n");
        return false;
    }

    if(!real_base.learned || !fake_base.initialized || !control_ack.learned)
    {
        nfq_destroy_queue(qh);
        nfq_close(h);

        std::fprintf(stderr, "[NFQ P-LEARN] learned state is invalid\n");
        return false;
    }

    /*
     * Important:
     * Remove the learning iptables rule while the NFQUEUE consumer is still alive.
     * Otherwise, packets can hit an NFQUEUE rule with no userspace queue attached
     * during the learning -> tunnel transition.
     */
    cleanup_proxy_nfqueue_rule(config, queue_num);

    nfq_destroy_queue(qh);
    nfq_close(h);

    if(!consume_tcp_learn_marker(client_fd, stop))
        return false;

    return true;
}

bool install_proxy_tunnel_nfqueue_rule(const ProxyRawConfig& config, uint16_t queue_num)
{
    return install_proxy_nfqueue_rule(config, queue_num);
}

void cleanup_proxy_tunnel_nfqueue_rule(const ProxyRawConfig& config, uint16_t queue_num)
{
    cleanup_proxy_nfqueue_rule(config, queue_num);
}

void proxy_tunnel_nfqueue_loop(uint16_t queue_num, const ProxyRawConfig& config, ProxyTunnelState& tunnel_state, std::atomic<bool>& stop)
{
    nfq_handle* h = nfq_open();
    if(h == nullptr)
    {
        std::fprintf(stderr, "[NFQ P-TUNNEL] nfq_open failed\n");
        tunnel_state.session_error.store(true);
        return;
    }

    if(nfq_unbind_pf(h, AF_INET) < 0)
    {
        std::fprintf(stderr, "[NFQ P-TUNNEL] nfq_unbind_pf(AF_INET) failed\n");
        nfq_close(h);
        tunnel_state.session_error.store(true);
        return;
    }

    if(nfq_bind_pf(h, AF_INET) < 0)
    {
        std::fprintf(stderr, "[NFQ P-TUNNEL] nfq_bind_pf(AF_INET) failed\n");
        nfq_close(h);
        tunnel_state.session_error.store(true);
        return;
    }

    ProxyTunnelNfqueueContext ctx;
    ctx.config = &config;
    ctx.tunnel_state = &tunnel_state;

    nfq_q_handle* qh = nfq_create_queue(h, queue_num, &proxy_tunnel_callback, &ctx);
    if(qh == nullptr)
    {
        std::fprintf(stderr, "[NFQ P-TUNNEL] nfq_create_queue failed\n");
        nfq_close(h);
        tunnel_state.session_error.store(true);
        return;
    }

    if(nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        std::fprintf(stderr, "[NFQ P-TUNNEL] nfq_set_mode failed\n");
        nfq_destroy_queue(qh);
        nfq_close(h);
        tunnel_state.session_error.store(true);
        return;
    }

    if(nfq_set_queue_maxlen(qh, 4096) < 0)
    {
        std::fprintf(stderr, "[NFQ P-TUNNEL] warning: nfq_set_queue_maxlen failed\n");
    }

    int fd = nfq_fd(h);
    char buf[4096];

    tunnel_state.nfqueue_ready.store(true);

    std::printf("[NFQ P-TUNNEL] tunnel NFQUEUE loop ready on queue %u\n", queue_num);

    while(!stop.load() && !tunnel_state.session_stop.load() && !tunnel_state.session_error.load())
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(fd + 1, &rfds, nullptr, nullptr, &tv);
        if(ret < 0)
        {
            if(errno == EINTR)
                continue;

            perror("[NFQ P-TUNNEL] select");
            tunnel_state.session_error.store(true);
            break;
        }

        if(ret == 0)
            continue;

        ssize_t rv = recv(fd, buf, sizeof(buf), 0);
        if(rv < 0)
        {
            if(errno == EINTR)
                continue;

            perror("[NFQ P-TUNNEL] recv");
            tunnel_state.session_error.store(true);
            break;
        }

        nfq_handle_packet(h, buf, static_cast<int>(rv));
    }

    tunnel_state.nfqueue_ready.store(false);

    nfq_destroy_queue(qh);
    nfq_close(h);

    std::printf("[NFQ P-TUNNEL] tunnel NFQUEUE loop stopped\n");
}
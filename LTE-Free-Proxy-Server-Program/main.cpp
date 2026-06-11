#include "proxy.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <atomic>
#include <thread>
#include <chrono>
#include <mutex>
#include <unistd.h>

static bool parse_port(const char* s, uint16_t& port)
{
    if(s == nullptr || s[0] == '\0')
        return false;

    char* end = nullptr;
    unsigned long value = std::strtoul(s, &end, 10);

    if(end == s || *end != '\0')
        return false;

    if(value == 0 || value > 65535)
        return false;

    port = static_cast<uint16_t>(value);
    return true;
}

static void usage(const char* prog)
{
    std::fprintf(stderr, "usage: %s <port>\n", prog);
    std::fprintf(stderr, "sample: %s 3502\n", prog);
}

static bool should_send_udp_stop(const ProxyReadyState& state)
{
    std::lock_guard<std::mutex> guard(state.lock);

    if(!state.registered)
        return false;

    if(state.stop_received)
        return false;

    return true;
}

int main(int argc, char* argv[])
{
    if(argc != 2)
    {
        usage(argv[0]);
        return 1;
    }

    uint16_t listen_port = 0;
    if(!parse_port(argv[1], listen_port))
    {
        std::fprintf(stderr, "invalid port: %s\n", argv[1]);
        return 1;
    }

    install_signal_handlers();

    int listen_fd = -1;
    int udp_fd = -1;

    /*
     * 1. TCP listen socket
     */
    listen_fd = listen_tcp(listen_port);
    if(listen_fd < 0)
    {
        std::fprintf(stderr, "failed to listen on port %u\n", listen_port);
        return 1;
    }

    /*
     * 2. UDP control socket
     *
     * TCP control port와 같은 번호의 UDP port를 사용한다.
     * TCP 3502와 UDP 3502는 서로 충돌하지 않는다.
     */
    udp_fd = open_proxy_ready_socket(listen_port);
    if(udp_fd < 0)
    {
        std::fprintf(stderr, "failed to open UDP ready socket on port %u\n", listen_port);
        close(listen_fd);
        return 1;
    }

    std::printf("[MAIN] proxy is ready. TCP/UDP port=%u\n", listen_port);

    while(!g_signal_stop)
    {
        std::atomic<bool> stop(false);

        int client_fd = -1;
        int tun_fd = -1;
        int raw_send_fd = -1;

        bool learning_rule_installed = false;
        bool tunnel_rule_installed = false;
        bool nat_rules_installed = false;

        bool udp_thread_started = false;
        bool tunnel_thread_started = false;
        bool raw_thread_started = false;

        sockaddr_in peer;
        ProxyRawConfig raw_config;
        ProxyReadyState ready_state;
        ProxyTunnelState tunnel_state;
        RealBase real_base;
        FakeBase fake_base;
        RawSendState raw_send_state;

        std::thread udp_thread;
        std::thread tunnel_thread;
        std::thread raw_thread;

        /*
         * 3. accept one client session
         */
        client_fd = accept_client_with_signal(listen_fd, peer);
        if(client_fd < 0)
        {
            if(g_signal_stop)
                break;

            std::fprintf(stderr, "[MAIN] failed to accept client\n");
            continue;
        }

        std::printf("[MAIN] client accepted\n");

        /*
         * 4. accepted client socket에 kernel TCP keepalive 설정
         *
         * TCP keepalive는 control connection 유지용이다.
         * Proxy learning은 keepalive ACK가 아니라,
         * Client가 TCP control socket으로 보내는 1-byte TCP_LEARN_MARKER를
         * Client -> Proxy 방향 NFQUEUE에서 관찰한다.
         */
        if(!set_tcp_keepalive(client_fd, 20, 1, 3))
        {
            std::fprintf(stderr, "[MAIN] failed to set TCP keepalive\n");
            stop.store(true);
        }

        /*
         * 5. raw config 초기화
         *
         * getsockname(client_fd)
         *   -> proxy_ip, proxy_port
         *
         * getpeername(client_fd)
         *   -> client_ip, client_port
         */
        if(!stop.load() && !init_proxy_raw_config(client_fd, raw_config))
        {
            std::fprintf(stderr, "[MAIN] failed to initialize proxy raw config\n");
            stop.store(true);
        }

        /*
         * 6. UDP REGISTER
         *
         * Client UDP endpoint와 nonce를 등록한다.
         */
        if(!stop.load() && !run_proxy_udp_register(udp_fd, ready_state, stop))
        {
            std::fprintf(stderr, "[MAIN] failed to complete UDP register\n");
            stop.store(true);
        }

        /*
         * 7. UDP control loop 시작
         *
         * REGISTER 이후의 UDP 수신은 이 thread 하나가 담당한다.
         */
        if(!stop.load())
        {
            udp_thread = std::thread(proxy_udp_control_loop,
                                     udp_fd,
                                     std::ref(ready_state),
                                     std::ref(tunnel_state),
                                     std::ref(stop));

            udp_thread_started = true;
        }

        /*
         * 8. learning NFQUEUE rule 설치
         *
         * ClientIP:ClientPort -> ProxyIP:ProxyPort 방향 packet만 queue로 보낸다.
         */
        if(!stop.load() && !install_proxy_nfqueue_rule(raw_config, PROXY_NFQUEUE_NUM))
        {
            std::fprintf(stderr, "[MAIN] failed to install proxy learning NFQUEUE rule\n");
            stop.store(true);
        }

        if(!stop.load())
            learning_rule_installed = true;

        /*
         * 9. realBase/fakeBase learning
         *
         * Proxy는 Client가 TCP control socket으로 보내는
         * 1-byte TCP_LEARN_MARKER를 Client -> Proxy 방향 NFQUEUE에서 관찰한다.
         *
         * marker packet:
         *   seq = client_next_before_marker
         *   ack = proxy_next
         *   payload_len = 1
         *
         * learned:
         *   realBase.client_seq = marker_seq
         *   realBase.proxy_seq  = marker_ack - 1
         *
         * initialized:
         *   fakeBase.fake_client_seq = marker_seq + 1
         *   fakeBase.fake_proxy_seq  = marker_ack
         */
        if(!stop.load() &&
           !learn_proxy_tcp_base_with_nfqueue(PROXY_NFQUEUE_NUM,
                                              client_fd,
                                              udp_fd,
                                              raw_config,
                                              ready_state,
                                              real_base,
                                              fake_base,
                                              tunnel_state.control_ack,
                                              stop))
        {
            std::fprintf(stderr, "[MAIN] failed to learn proxy TCP real/fake base\n");
            stop.store(true);
        }

        if(!stop.load() &&
           (!real_base.learned || !fake_base.initialized || !tunnel_state.control_ack.learned))
        {
            std::fprintf(stderr, "[MAIN] base learning state is invalid\n");
            stop.store(true);
        }

        /*
         * learn_proxy_tcp_base_with_nfqueue() 성공 시 내부에서 learning rule을 삭제한다.
         * main의 상태값도 맞춰서 cleanup 때 중복 삭제를 피한다.
         */
        if(!stop.load())
            learning_rule_installed = false;

        if(!stop.load())
        {
            std::printf("[MAIN] realBase learned\n");
            std::printf("[MAIN] client_seq=%u\n", real_base.client_seq);
            std::printf("[MAIN] proxy_seq =%u\n", real_base.proxy_seq);

            std::printf("[MAIN] fakeBase initialized\n");
            std::printf("[MAIN] fake_client_seq=%u\n", fake_base.fake_client_seq);
            std::printf("[MAIN] fake_proxy_seq =%u\n", fake_base.fake_proxy_seq);
        }

        /*
         * 10. learning rule cleanup
         *
         * learning 실패 경로에서는 rule이 남아 있을 수 있으므로 여기서 정리한다.
         * learning 성공 경로에서는 learning_rule_installed가 false로 바뀌어 실행되지 않는다.
         */
        if(learning_rule_installed)
        {
            cleanup_proxy_nfqueue_rule(raw_config, PROXY_NFQUEUE_NUM);
            learning_rule_installed = false;
        }

        /*
         * 11. tunnel NFQUEUE rule 설치
         */
        if(!stop.load() && !install_proxy_tunnel_nfqueue_rule(raw_config, PROXY_NFQUEUE_NUM))
        {
            std::fprintf(stderr, "[MAIN] failed to install proxy tunnel NFQUEUE rule\n");
            stop.store(true);
        }

        if(!stop.load())
            tunnel_rule_installed = true;

        /*
         * 12. tunnel NFQUEUE loop 시작
         */
        if(!stop.load())
        {
            tunnel_thread = std::thread(proxy_tunnel_nfqueue_loop,
                                        PROXY_NFQUEUE_NUM,
                                        std::cref(raw_config),
                                        std::ref(tunnel_state),
                                        std::ref(stop));

            tunnel_thread_started = true;
        }

        /*
         * 13. local tunnel NFQUEUE ready 대기
         */
        while(!g_signal_stop &&
              !stop.load() &&
              !tunnel_state.nfqueue_ready.load() &&
              !tunnel_state.session_error.load())
        {
            usleep(10 * 1000);
        }

        if(!stop.load() && !tunnel_state.nfqueue_ready.load())
        {
            std::fprintf(stderr, "[MAIN] tunnel NFQUEUE did not become ready\n");
            stop.store(true);
        }

        /*
         * 14. UDP READY handshake
         *
         * local tunnel NFQUEUE가 실제로 준비된 뒤에만 수행한다.
         */
        if(!stop.load() && !run_proxy_ready_handshake(udp_fd, ready_state, stop))
        {
            std::fprintf(stderr, "[MAIN] failed to complete UDP READY handshake\n");
            stop.store(true);
        }

        if(!stop.load())
        {
            std::printf("[MAIN] UDP READY handshake done\n");
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }

        /*
         * 15. tunP0 생성/설정
         */
        if(!stop.load())
        {
            tun_fd = tun_alloc(PROXY_TUN_NAME);
            if(tun_fd < 0)
            {
                std::fprintf(stderr, "[MAIN] failed to allocate tunP0\n");
                stop.store(true);
            }
        }

        if(!stop.load() && !setup_tun_interface(PROXY_TUN_NAME))
        {
            std::fprintf(stderr, "[MAIN] failed to setup tunP0\n");
            stop.store(true);
        }

        if(!stop.load() && !set_nonblocking(tun_fd))
        {
            std::fprintf(stderr, "[MAIN] failed to set tunP0 nonblocking\n");
            stop.store(true);
        }

        /*
         * 16. NAT/FORWARD rule 설치
         */
        if(!stop.load() && !setup_nat_rules())
        {
            std::fprintf(stderr, "[MAIN] failed to setup NAT/FORWARD rules\n");
            cleanup_nat_rules();
            stop.store(true);
        }

        if(!stop.load())
            nat_rules_installed = true;

        /*
         * 17. raw send socket 생성
         */
        if(!stop.load())
        {
            raw_send_fd = open_raw_send_socket();
            if(raw_send_fd < 0)
            {
                std::fprintf(stderr, "[MAIN] failed to open raw send socket\n");
                stop.store(true);
            }
        }

        /*
         * 18. tunP0 -> Client raw send thread 시작
         */
        if(!stop.load())
        {
            raw_thread = std::thread(tun_to_raw_loop,
                                     tun_fd,
                                     raw_send_fd,
                                     std::cref(raw_config),
                                     std::cref(fake_base),
                                     std::ref(raw_send_state),
                                     std::ref(stop));

            raw_thread_started = true;
        }

        /*
         * 19. tunnel_state에 tun fd 등록
         *
         * tunP0, NAT/FORWARD, raw socket, raw send thread가 준비된 뒤에만
         * data_plane_ready를 true로 만든다.
         */
        if(!stop.load())
        {
            tunnel_state.tun_fd.store(tun_fd);
            tunnel_state.data_plane_ready.store(true);
        }

        if(!stop.load())
        {
            std::printf("[MAIN] proxy data plane started\n");
        }

        /*
         * 20. session wait loop
         *
         * Client와 달리 Proxy는 Enter를 기다리지 않는다.
         * Ctrl+C / UDP STOP / session_error 기준으로 session을 종료한다.
         */
        while(!g_signal_stop &&
              !stop.load() &&
              !tunnel_state.session_stop.load() &&
              !tunnel_state.session_error.load())
        {
            sleep(1);
        }

        /*
         * session cleanup
         */
        if(should_send_udp_stop(ready_state))
            send_proxy_udp_stop(udp_fd, ready_state);

        stop.store(true);
        tunnel_state.data_plane_ready.store(false);
        tunnel_state.session_stop.store(true);

        if(tunnel_rule_installed)
        {
            cleanup_proxy_tunnel_nfqueue_rule(raw_config, PROXY_NFQUEUE_NUM);
            tunnel_rule_installed = false;
        }

        if(learning_rule_installed)
        {
            cleanup_proxy_nfqueue_rule(raw_config, PROXY_NFQUEUE_NUM);
            learning_rule_installed = false;
        }

        if(raw_thread_started && raw_thread.joinable())
            raw_thread.join();

        if(tunnel_thread_started && tunnel_thread.joinable())
            tunnel_thread.join();

        if(udp_thread_started && udp_thread.joinable())
            udp_thread.join();

        if(nat_rules_installed)
        {
            cleanup_nat_rules();
            nat_rules_installed = false;
        }

        if(raw_send_fd >= 0)
            close(raw_send_fd);

        if(tun_fd >= 0)
            close(tun_fd);

        if(client_fd >= 0)
            close(client_fd);

        std::printf("[MAIN] proxy session cleaned up\n");

        if(g_signal_stop)
            break;

        std::printf("[MAIN] waiting for next client\n");
    }

    if(udp_fd >= 0)
        close(udp_fd);

    if(listen_fd >= 0)
        close(listen_fd);

    std::printf("proxy stopped\n");

    return 0;
}
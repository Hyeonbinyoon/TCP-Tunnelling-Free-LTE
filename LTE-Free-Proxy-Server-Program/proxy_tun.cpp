#include "proxy.h"

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <string>
#include <thread>
#include <chrono>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <linux/if.h>
#include <linux/if_tun.h>

int tun_alloc(const char* dev_name)
{
    int fd = open("/dev/net/tun", O_RDWR);
    if(fd < 0)
    {
        perror("open /dev/net/tun");
        return -1;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));

    /*
     * IFF_TUN   : L3 IP packet 단위 TUN 인터페이스
     * IFF_NO_PI : 앞에 4바이트 packet information을 붙이지 않음
     */
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if(dev_name != nullptr && dev_name[0] != '\0')
    {
        std::strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    }

    if(ioctl(fd, TUNSETIFF, &ifr) < 0)
    {
        perror("ioctl TUNSETIFF");
        close(fd);
        return -1;
    }

    std::printf("created TUN device: %s\n", ifr.ifr_name);
    return fd;
}

bool setup_tun_interface(const char* dev_name)
{
    std::string dev = dev_name;

    if(!run_cmd("sysctl -w net.ipv6.conf." + dev + ".disable_ipv6=1"))
        return false;

    if(!run_cmd("ip addr add " + std::string(PROXY_TUN_IP_CIDR) + " dev " + dev))
        return false;

    if(!run_cmd("ip link set dev " + dev + " mtu " + std::to_string(TUN_MTU)))
        return false;

    if(!run_cmd("ip link set dev " + dev + " up"))
        return false;

    return true;
}

bool write_packet_to_tun(int tun_fd, const std::vector<uint8_t>& packet)
{
    ssize_t n = write(tun_fd, packet.data(), packet.size());
    if(n < 0)
    {
        if(errno == EINTR && g_signal_stop)
            return false;

        perror("write tun");
        return false;
    }

    if(static_cast<size_t>(n) != packet.size())
    {
        std::fprintf(stderr, "partial tun write: %zd / %zu\n", n, packet.size());
        return false;
    }

    std::printf("wrote %zu bytes to tunP0\n", packet.size());
    return true;
}

/*void tun_to_client_loop(int tun_fd, int client_fd, std::atomic<bool>& stop)
{
    uint8_t buf[2000];

    while(!stop.load() && !g_signal_stop)
    {
        ssize_t n = read(tun_fd, buf, sizeof(buf));
        if(n < 0)
        {
            if(stop.load() || g_signal_stop)
                break;

            if(errno == EINTR)
                continue;

            if(errno == EAGAIN || errno == EWOULDBLOCK)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }

            perror("[P->C] read tun");
            stop.store(true);
            break;
        }

        if(n == 0)
        {
            std::fprintf(stderr, "[P->C] tun read returned 0\n");
            stop.store(true);
            break;
        }

        std::printf("[P->C] read %zd bytes from tunP0\n", n);

        if(!send_all(client_fd, buf, static_cast<size_t>(n)))
        {
            std::fprintf(stderr, "[P->C] failed to send packet to client\n");
            stop.store(true);
            break;
        }

        std::printf("[P->C] sent %zd bytes to client\n", n);
    }
}*/

#include "proxy.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

volatile std::sig_atomic_t g_signal_stop = 0;

static void handle_signal(int)
{
    g_signal_stop = 1;
}

void install_signal_handlers()
{
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));

    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);

    if(sigaction(SIGINT, &sa, nullptr) < 0)
        perror("sigaction SIGINT");

    if(sigaction(SIGTERM, &sa, nullptr) < 0)
        perror("sigaction SIGTERM");
}

bool set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if(flags < 0)
    {
        perror("fcntl F_GETFL");
        return false;
    }

    if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        perror("fcntl F_SETFL O_NONBLOCK");
        return false;
    }

    return true;
}

bool run_cmd(const std::string& cmd)
{
    int ret = std::system(cmd.c_str());
    if(ret != 0)
    {
        std::fprintf(stderr, "command failed: %s\n", cmd.c_str());
        return false;
    }

    return true;
}

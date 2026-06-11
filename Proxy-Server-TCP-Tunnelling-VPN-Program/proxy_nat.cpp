#include "proxy.h"

#include <string>

bool setup_nat_rules()
{
    if(!run_cmd("sysctl -w net.ipv4.ip_forward=1"))
        return false;

    if(!run_cmd("iptables -A FORWARD "
                "-i " + std::string(PROXY_TUN_NAME) + " "
                "-s " + std::string(CLIENT_TUN_IP) + "/32 "
                "-o " + std::string(PROXY_EXTERNAL_IFNAME) + " "
                "-m comment --comment " + std::string(SESSION_COMMENT) + " "
                "-j ACCEPT"))
        return false;

    if(!run_cmd("iptables -A FORWARD "
                "-i " + std::string(PROXY_EXTERNAL_IFNAME) + " "
                "-o " + std::string(PROXY_TUN_NAME) + " "
                "-d " + std::string(CLIENT_TUN_IP) + "/32 "
                "-m conntrack --ctstate ESTABLISHED,RELATED "
                "-m comment --comment " + std::string(SESSION_COMMENT) + " "
                "-j ACCEPT"))
        return false;

    if(!run_cmd("iptables -t nat -A POSTROUTING "
                "-s " + std::string(CLIENT_TUN_IP) + "/32 "
                "-o " + std::string(PROXY_EXTERNAL_IFNAME) + " "
                "-m comment --comment " + std::string(SESSION_COMMENT) + " "
                "-j MASQUERADE"))
        return false;

    return true;
}

void cleanup_nat_rules()
{
    run_cmd("iptables -t nat -D POSTROUTING "
            "-s " + std::string(CLIENT_TUN_IP) + "/32 "
            "-o " + std::string(PROXY_EXTERNAL_IFNAME) + " "
            "-m comment --comment " + std::string(SESSION_COMMENT) + " "
            "-j MASQUERADE 2>/dev/null");

    run_cmd("iptables -D FORWARD "
            "-i " + std::string(PROXY_EXTERNAL_IFNAME) + " "
            "-o " + std::string(PROXY_TUN_NAME) + " "
            "-d " + std::string(CLIENT_TUN_IP) + "/32 "
            "-m conntrack --ctstate ESTABLISHED,RELATED "
            "-m comment --comment " + std::string(SESSION_COMMENT) + " "
            "-j ACCEPT 2>/dev/null");

    run_cmd("iptables -D FORWARD "
            "-i " + std::string(PROXY_TUN_NAME) + " "
            "-s " + std::string(CLIENT_TUN_IP) + "/32 "
            "-o " + std::string(PROXY_EXTERNAL_IFNAME) + " "
            "-m comment --comment " + std::string(SESSION_COMMENT) + " "
            "-j ACCEPT 2>/dev/null");
}

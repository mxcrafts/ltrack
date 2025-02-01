#include "../headers/vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/ // ipv4
#define ETH_HLEN 14 /* Total octets in header.	 */


struct event_t {
    __u32 src_addr;
    __u32 dst_addr;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u32 data_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("xdp")
int handle_xdp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. 验证以太网头部
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 2. 只处理 IPv4 数据包
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 3. 验证 IP 头部
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // 4. 只处理 TCP/UDP 数据包
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // 5. 根据协议类型处理
    __u16 src_port = 0;
    __u16 dst_port = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
    } else {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    }

    // 6. 创建并发送事件
    struct event_t event = {
        .src_addr = bpf_ntohl(ip->saddr),
        .dst_addr = bpf_ntohl(ip->daddr),
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = ip->protocol,
        .data_len = (u32)(data_end - data),
    };

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
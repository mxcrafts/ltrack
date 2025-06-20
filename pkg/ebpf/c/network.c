#include "../headers/vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/ // ipv4
#define ETH_HLEN 14 /* Total octets in header.	 */

// 简化事件结构，减少寄存器使用
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

// XDP程序入口点 - 简化版
SEC("xdp")
int handle_xdp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 确保我们至少有一个以太网头部
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;
    }
    
    struct ethhdr *eth = data;
    
    // 只处理IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    // 检查IP头部
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }
    
    // 只处理TCP和UDP
    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }
    
    __u16 src_port = 0;
    __u16 dst_port = 0;
    
    // TCP数据包
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(iph + 1);
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
    } 
    // UDP数据包
    else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(iph + 1);
        if ((void *)(udp + 1) > data_end) {
            return XDP_PASS;
        }
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    }
    
    // 创建事件
    struct event_t event;
    __builtin_memset(&event, 0, sizeof(event));
    
    event.src_addr = iph->saddr;
    event.dst_addr = iph->daddr;
    event.src_port = src_port;
    event.dst_port = dst_port;
    event.protocol = iph->protocol;
    event.data_len = (__u32)(data_end - data);
    
    // 发送事件
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return XDP_PASS;
}

// TC程序入口点 - 入站流量
SEC("tc")
int handle_tc_ingress(struct __sk_buff *skb) {
    return XDP_PASS;
}

// TC程序入口点 - 出站流量
SEC("tc")
int handle_tc_egress(struct __sk_buff *skb) {
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
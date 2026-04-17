#include "protocols.h"
#include "queue.h"
#include "lib.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#define IPv4 0x0800
#define ARP 0x0806
#define ARP_REQ 1
#define ARP_REP 2

#define ICMP_DESTINATION_UNREACHED 3
#define ICMP_TIME_EXCEEDED 11
#define ICMP_ECHO_REQ 8
#define ICMP_ECHO_REPLY 0


struct route_table_entry *rtable;
int rtable_len;

struct arp_table_entry *mac_table;

struct route_table_entry *get_best_route(uint32_t destination_ip)
{
    //* Linear aproach for the LPM

    struct route_table_entry *best_route = NULL;
    uint32_t longest_mask = 0;

    int i = 0;

    while(i < rtable_len)
    {
        uint32_t mask = rtable[i].mask;
        uint32_t network_prefix = rtable[i].prefix & mask;

        if ((destination_ip & mask) == network_prefix)
        {
            if (mask > longest_mask)
            {
                longest_mask = mask;
                best_route = &rtable[i];
            }
        }
        i++;
    }
    return best_route;
}

void icmp_echo_reply(struct icmp_hdr *icmp_header,
                        struct ip_hdr *ip_header,
                        struct ether_hdr *ether_header,
                        int interface,
                        char *packet,
                        size_t len)
{
    //* Swap dest and source MAC addresses
    uint8_t tmp_mac[6];
    memcpy(tmp_mac, ether_header->ethr_dhost, 6);
    memcpy(ether_header->ethr_dhost, ether_header->ethr_shost, 6);
    memcpy(ether_header->ethr_shost, tmp_mac, 6);

    //* Swap dest and source IP addresses
    uint32_t tmp_ip = ip_header->source_addr;
    ip_header->source_addr = ip_header->dest_addr;
    ip_header->dest_addr = tmp_ip;

    //* Recalculate IP checksum
    ip_header->checksum = 0;
    ip_header->checksum = htons(checksum((uint16_t *)ip_header, sizeof(struct ip_hdr)));

    //* Change type to Echo Reply
    icmp_header->mtype = ICMP_ECHO_REPLY;

    //* Recalculate ICMP checksum
    icmp_header->check = 0;
    size_t icmp_len = len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr);
    icmp_header->check = htons(checksum((uint16_t *)icmp_header, icmp_len));

    //! We ball
    send_to_link(len, packet, interface);
}

void icmp_error(struct ip_hdr *ip_header,
                        struct ether_hdr *ether_header,
                        int interface,
                        char *packet,
                        size_t len,
                        int type)
{

    //* Swap dest and source MAC addresses
    uint8_t tmp_mac[6];
    memcpy(tmp_mac, ether_header->ethr_dhost, 6);
    memcpy(ether_header->ethr_dhost, ether_header->ethr_shost, 6);
    memcpy(ether_header->ethr_shost, tmp_mac, 6);

    //* Save original ip header
    struct ip_hdr original_ip;
    memcpy(&original_ip, ip_header, sizeof(struct ip_hdr));

    //* Save ICMP evidence
    char original_payload[8];
    memcpy(original_payload, (char *)ip_header + sizeof(struct ip_hdr), 8);

    ip_header->ver = 4;
    ip_header->ihl = 5;
    ip_header->tos = 0;
    ip_header->id = htons(4);
    ip_header->frag = 0;
    ip_header->ttl = 64;
    ip_header->proto = IPPROTO_ICMP;
    ip_header->source_addr = inet_addr(get_interface_ip(interface));
    ip_header->dest_addr = original_ip.source_addr;

    size_t icmp_payload_len = sizeof(struct ip_hdr) + 8;
    ip_header->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + icmp_payload_len);

    //* IP checksum
    ip_header->checksum = 0;
    ip_header->checksum = htons(checksum((uint16_t *)ip_header, sizeof(struct ip_hdr)));

    //* Build ICMP header
    struct icmp_hdr *icmp_header = (struct icmp_hdr *)((char *)ip_header + sizeof(struct ip_hdr));

    if(type == 11)
        icmp_header->mtype = ICMP_TIME_EXCEEDED;
    else if(type == 3)
        icmp_header->mtype = ICMP_DESTINATION_UNREACHED;

    icmp_header->mcode = 0;
    icmp_header->check = 0;
    icmp_header->un_t.echo_t.id = 0;
    icmp_header->un_t.echo_t.seq = 0;

    //* Copy original IP header + 8 bytes from original payload (ICMP evidence)
    char *icmp_payload = (char *)icmp_header + sizeof(struct icmp_hdr);
    memcpy(icmp_payload, &original_ip, sizeof(struct ip_hdr));
    memcpy(icmp_payload + sizeof(struct ip_hdr), original_payload, 8);

    //* ICMP checksum
    size_t icmp_total_len = sizeof(struct icmp_hdr) + icmp_payload_len;
    icmp_header->check = htons(checksum((uint16_t *)icmp_header, icmp_total_len));

    //! Send it
    size_t total_len = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + icmp_total_len;
    send_to_link(total_len, packet, interface);
}

int main(int argc, char *argv[])
{
    char buf[MAX_PACKET_LEN];

    // Do not modify this line
    init(argv + 2, argc - 2);

    rtable = malloc(sizeof(struct route_table_entry) * 67000);
    mac_table = malloc(sizeof(struct arp_table_entry) * 67000);

    rtable_len = read_rtable(argv[1], rtable);

    while (1) {

        size_t interface;
        size_t len;

        interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");


        struct ether_hdr *ether_header = (struct ether_hdr *)buf;

        //? IPv4 case
        if(ntohs(ether_header->ethr_type) == IPv4)
        {
            struct ip_hdr *ip_header = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

            //* The package is for the router
            if(ip_header->dest_addr == inet_addr(get_interface_ip(interface)))
            {
                struct icmp_hdr *icmp_header = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

                //^ The package is ICMP-Echo-request => ICMP_ECHO_REPLY
                if(ip_header->proto == IPPROTO_ICMP && icmp_header->mtype == ICMP_ECHO_REQ)
                {
                    icmp_echo_reply(icmp_header, ip_header, ether_header, interface, buf, len);
                    continue;
                }
            }

            //* TTL check
            if(ip_header->ttl <= 1)
            {
                icmp_error(ip_header, ether_header, interface, buf, len, ICMP_TIME_EXCEEDED);
                continue;
            }

            //* Checksum check
            uint16_t checksum_copy = ip_header->checksum;
            ip_header->checksum = 0;
            if(ntohs(checksum((uint16_t *)ip_header, sizeof(struct ip_hdr))) != checksum_copy)
            {
                continue;
            }
            ip_header->checksum = checksum_copy;

            //* Checking for the best route in the route table
                //^ If there is no route found => ICMP_DESTINATION_UNREACHED
            struct route_table_entry *best_route = get_best_route(ip_header->dest_addr);
            if(!best_route)
            {
                icmp_error(ip_header, ether_header, interface, buf, len, ICMP_DESTINATION_UNREACHED);
                continue;
            }

            //* Everything went great so we change parameters
            ip_header->ttl --;
            ip_header->checksum = 0;
            ip_header->checksum = ntohs(checksum((u_int16_t *)ip_header, sizeof(struct ip_hdr)));

            get_interface_mac(best_route->interface, ether_header->ethr_shost);

            //! We send it
            send_to_link(len, buf, best_route->interface);
        }
        //? ARP case
        else if (ntohs(ether_header->ethr_type) == ARP)
        {
            struct arp_hdr *arp_header = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

            if (ntohs(arp_header->opcode) == ARP_REQ)
            {
                if (arp_header->tprotoa == inet_addr(get_interface_ip(interface)))
                {
                    arp_header->opcode = htons(ARP_REP);

                    memcpy(arp_header->thwa, arp_header->shwa, 6);
                    get_interface_mac(interface, arp_header->shwa);

                    arp_header->tprotoa = arp_header->sprotoa;
                    arp_header->sprotoa = inet_addr(get_interface_ip(interface));

                    memcpy(ether_header->ethr_dhost, ether_header->ethr_shost, 6);
                    get_interface_mac(interface, ether_header->ethr_shost);

                    send_to_link(len, buf, interface);
                }
            }
        }
    }
}

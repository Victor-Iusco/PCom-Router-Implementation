# PCom 1 - router

## Iusco Victor Stefan - 332CB


### Task 1 - Procesul de dirijare.

    For this task, I implemented the core functionality of a router
    when receiving an IPv4 packet, following the standard routing protocol:

    After verifing the package is of IPv4 type, we check who is the final destination.
    In the case where the router is the final destination we send an ICMP-echo_reply

    We check the TTL, checksum and best_route to the destination, and handle the
    situations accordingly and if everything is good

    change : TTL , CHECKSUM and SENDER-ADDRESS

    and send it on the interface

### Task 3 - ARP

    For the ARP case, I implemented only the ARP reply, my router being unable to send
    arp-replys.

    After we verify the package is an ARP-request (the only one we handle)
    We change the code of the package to an ARP reply, we swap the source and destination
    hardware and IP addresses and send it back.

### Task 4 - ICMP

    While checking the IPv4 package we received, we check if the package expired
    (Time To Live <= 1), in which case we will send an ICMP-time-exceeded package,
    and if the best_route is not found , we send an ICMP-destination-unreachable package.

    In both cases we swap the destination and source MAC and IP addresses, we populate
    the fields with the necesary information, while adding 8 bytes from the original
    payload as an `ICMP evidence`

    We recalculate checksum and we send it.

### Checker RAN:

    Starting router0
    Starting router1

        router_arp_reply ..................................................   PASSED [15]
      router_arp_request ..................................................   FAILED [ 0]
                forward ..................................................   PASSED [ 3]
          forward_no_arp ..................................................   PASSED [ 3]
                    ttl ..................................................   PASSED [ 3]
                checksum ..................................................   PASSED [ 3]
          wrong_checksum ..................................................   PASSED [ 3]
              forward03 ..................................................   PASSED [ 3]
              forward10 ..................................................   PASSED [ 3]
              forward20 ..................................................   PASSED [ 3]
              forward21 ..................................................   PASSED [ 3]
              forward23 ..................................................   PASSED [ 3]
              forward31 ..................................................   PASSED [ 3]
            router_icmp ..................................................   PASSED [ 7]
            icmp_timeout ..................................................   PASSED [ 7]
        host_unreachable ..................................................   PASSED [ 7]
        forward10packets ..................................................   FAILED [ 0]
        forward10across ..................................................   FAILED [ 0]

    TOTAL: 69/100

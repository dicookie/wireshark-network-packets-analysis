# wireshark Network Packets Analysis

Wireshark is a powerful network protocol analyzer that allows users to capture and interactively browse the traffic running on a computer network. It enables deep inspection of hundreds of protocols. Wireshark provides detailed packet information, making it valuable for network analysis and security auditing tasks. It is a critical tool for network administrators and security professionals.

Wireshark network packet analysis involves using Wireshark to capture, examine, and interpret network packets on a computer network. Analysts use Wireshark’s comprehensive tools to inspect packets and analyze network behaviors. It helps with diagnosing network performance issues, investigating security incidents, and ensuring compliance with network policies.

![https://i.postimg.cc/25nmbBbR/0.jpg]

In this analysis, I will demonstrate how to analyze various network traffic using Wireshark. By examining packet captures, we will also identify and understand different types of network attacks. There are a total of 4 scenarios, each of which contains the process taken to analyze the packets, potential attack explanations, and security recommendations to mitigate such attacks.

## Scenario 1: ARP & FTP Analysis

### Introduction

In this capture file `example.pcap`, the objective is to analyze ARP requests and responses, and then look at FTP. The goal is to identify the MAC address and IP address of the requester, the first device to respond, the number of responding devices, the protocol used for data transfer, and the login credentials for data transfer.

### Steps

1. Apply the filter `arp && arp.opcode == 1 && arp.dst.proto_ipv4 == 192.168.1.221`. We find that the requestor’s MAC address is `Verizon_c2:69:24 (20:c0:47:c2:69:24)` and the IP address is `192.168.1.1`.

    ![https://i.postimg.cc/501JwNLH/1.jpg]

2. Apply the filter `arp && arp.opcode == 2 && arp.src.proto_ipv4 == 192.168.1.221`. We observe that there are 3 ARP reply packets.

    ![https://i.postimg.cc/5yKMdBGv/2-1.jpg]

3. We find that the first responder’s MAC address is `RaspberryPiF_64:8a:24 (b8:27:eb:64:8a:24)` and the IP address is `192.168.1.221`.

    !https://i.postimg.cc/FRZ4G5VT/2-2.jpg]

4. Apply the filter `ip.dst == 192.168.1.221`. We identify that FTP was used for data transfer.

    ![https://i.postimg.cc/TYSXtcnv/3.jpg]

5. Apply the filter `ftp && ip.dst == 192.168.1.221`. We find that the username is `pikachu` and the password is `INeverLikedPokemon`.

    ![https://i.postimg.cc/c1FWnWHH/4.jpg]

### Potential Attack Explanation

One significant problem with FTP is that it transmits data in plain text without any encryption. That means any malicious actor who intercepts the network traffic can read, modify, or steal sensitive information. This can lead to data breaches, identity theft, and other malicious attacks.

### Security Recommendation

To mitigate these risks, always opt for a secure version of FTP. FTPS (FTP Secure) or SFTP (SSH File Transfer Protocol) both provide encryption and authentication mechanisms, making them far more secure than standard FTP. Additionally, consider using file transfer solutions or web applications integrated with enhanced security measures such as multi-factor authentication and file integrity validation. One thing to remember is to avoid using FTP over public or untrusted networks to protect your data.

## Scenario 2: ARP Spoofing Attack

### Introduction

In the capture file `network_attack.pcap`, the goal is to review ARP packets and identify an ARP spoofing attack.

### Steps

1. Apply the filter `arp`.

    ![https://i.postimg.cc/cCLNb9D0/5.jpg]

2. We observe that there are 3 packets: packet 1 is an ARP request, packet 2 is a legitimate ARP reply, and packet 3 is a forged ARP reply.

    ![https://i.postimg.cc/zfYYrXdd/6-1.jpg]

3. We find the legitimate device’s MAC address is `VMware_f9:f5:54 (00:50:56:f9:f5:54)` and IP address is `192.168.47.254`.

    ![https://i.postimg.cc/CxqpXf4B/6-2.jpg]

4. We also find that the hacker’s MAC address is `VMware_1d:b3:b1 (00:0c:29:1d:b3:b1)`.

    ![https://i.postimg.cc/KY7SvSw-m/7.jpg]

### Potential Attack Explanation

ARP (Address Resolution Protocol) spoofing, also known as ARP poisoning, is a type of attack where an attacker sends forged ARP messages over a LAN. This results in the linking of the attacker’s MAC address with the IP address of a legitimate computer or server on the network. Once done, the attacker can intercept, modify, or stop data intended for that IP address. This can lead to data theft, DoS, session hijacking, and other attacks.

### Security Recommendation

To mitigate the risks of ARP spoofing, consider implementing DAI (Dynamic ARP Inspection) on network switches, using static ARP entries where feasible, employing ARP spoofing detection tools, and monitoring network traffic for unusual ARP activity. These methods can help identify and prevent such attacks.

## Scenario 3: DHCP Starvation Attack

### Introduction

In the capture file `network_attack.pcap`, the goal is to identify and analyze a DHCP starvation attack.

### Steps

1. Apply the filter `dhcp`.

    ![https://i.postimg.cc/FzBwn9dV/8-1.jpg]

2. We find numerous DHCP Discover packets from `0.0.0.0` to `255.255.255.255`. `255.255.255.255` is a broadcast address to reach all devices, including DHCP servers.

    ![https://i.postimg.cc/3RKMkfQm/8-2.jpg]

### Potential Attack Explanation

A Dynamic Host Configuration Protocol Server is responsible for issuing IP addresses to devices on its network. This is done through a series of packet exchanges between individual DHCP clients and DHCP servers (DISCOVER, OFFER, REQUEST, ACKNOWLEDGEMENT). In a DHCP starvation attack, the malicious actor sends numerous DISCOVER packets until the IP address pool of a DHCP server is exhausted. This prevents legitimate users from getting IP addresses, causing Denial of Service, network disruption, and other harms.

### Security Recommendations

To prevent DHCP starvation attacks, implement DHCP snooping on network switches to filter out DHCP traffic from untrusted sources and ensure only trusted ports can send DHCP requests. For critical devices, use static IP addresses to reduce reliance on DHCP and ensure network connectivity during an attack. Also, regularly monitor network traffic and use IDS to detect and alert on potential DHCP traffic.

## Scenario 4: TCP SYN Flood

### Introduction

In the capture file `network_attack.pcap`, the goal is to identify and analyze a TCP SYN flood attack.

### Steps

1. Apply the filter `tcp`.

    ![https://i.postimg.cc/Wz3QnD34/9-1.jpg]

2. We see a large amount of TCP SYN packets sent to a target IP address without completing the three-way handshake.

    ![https://i.postimg.cc/nzTyBKn5/9-2.jpg]

### Potential Attack Explanation

After reviewing the packets, we identify this as a potential TCP SYN flood attack. The TCP SYN flood is where the attacker exploits the TCP three-way handshake process by sending numerous TCP SYN packets to a target server to overwhelm it. The attacker does not complete the handshake, which leaves the server with numerous half-open connections. This attack can lead to resource exhaustion, DoS, and network congestion.

### Security Recommendations

Implement SYN flood protection mechanisms such as SYN cookies, rate limiting, IPS, and firewall rules to mitigate the impact of SYN flood attacks. Also, increasing the size of the backlog queue to handle more half-open connections will reduce the likelihood of resource depletion.

## Conclusion

In this analysis, we looked at various network traffic patterns and attacks using Wireshark. Packet captures provide us with methods to identify and analyze attacks, potential harms, and effective security recommendations to mitigate them. These are crucial steps to protect network infrastructure and maintain the confidentiality, integrity, and availability of network services.

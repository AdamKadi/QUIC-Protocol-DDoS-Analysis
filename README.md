# Network Traffic Extraction Using tcpdump

## Overview

This README provides details about the network traffic extraction process that was conducted using `tcpdump`. The traffic emulations were performed in a virtualized environment utilizing Proxmox. Below, we outline the setup of the environment, the roles of various virtual machines (VMs), and the specifics of the traffic captured in the `pcap` files.

## Environment Setup

### Proxmox Virtual Environment

Proxmox is an open-source server virtualization environment that allows the creation and management of virtual machines and containers. In our setup, Proxmox was used to create and manage the virtualized infrastructure necessary for our network traffic emulation.

### Web Server Details

- **IP Address**: 172.19.0.8
- **Server Type**: NGINX
- **Protocol**: HTTP/3
- **Port**: 443

The server hosted on the VM with the IP address `172.19.0.8` serves as an HTTP/3 web server running NGINX. This server was the primary target for the DDoS attacks simulated in our study.

## Network Traffic Emulation

### Normal Traffic Emulation

All IP addresses starting with `172.19...` belong to virtual machines that execute a Python script using the Selenium library. These scripts launch a web client emulator that navigates to the web server, simulating normal background traffic. The objective of this setup is to create realistic web browsing behavior to mix with the attack traffic.

### DDoS Attack Simulation

All IP addresses starting with `172.16...` are assigned to virtual machines designated as bots. These bots are responsible for launching DDoS attacks against the web server at `172.19.0.8`. The attacks are designed to test the resilience and performance of the web server under malicious load.

## Traffic Capture with tcpdump

The network traffic was captured using the `tcpdump` tool. Tcpdump is a powerful command-line packet analyzer that allows the capture and analysis of network traffic.

### Example Command

To capture traffic, the following `tcpdump` command was used:

```bash
sudo tcpdump -i <interface> -w traffic_capture.pcap
```

## Definition of a Bidirectional Network Flow for an HTTP/3 Web Server

A bidirectional network flow refers to a set of communications between two points on a network, characterized by the exchange of packets in both directions. In the context of a web server using the HTTP/3 protocol, these flows are particularly relevant to understanding how data travels between a client and a server.

## Key Concepts

1. **Source and Destination IP Address:**
   - **Source IP Address:** The IP address of the device sending the initial packet. In the case of a client connecting to a web server, the source IP address is that of the client.
   - **Destination IP Address:** The IP address of the device receiving the packet. For an HTTP/3 web server, this is the IP address of the server.

2. **Source and Destination Port:**
   - **Source Port:** The port number on the source device (client) from which the packet is sent. Source ports are often dynamically chosen by the client.
   - **Destination Port:** The port number on the destination device (server) to which the packet is sent. For HTTP/3, the standard port used is typically port 443.

3. **Protocol:**
   - The protocol used for communications. HTTP/3 uses the QUIC (Quick UDP Internet Connections) protocol, which is a transport protocol based on UDP.

## Definition of the Bidirectional Flow

A bidirectional flow for an HTTP/3 web server groups all packets exchanged between an IP address and port of the client and the IP address and port of the web server. Here’s how it is defined:

- **Flow towards the server (incoming):** Each packet sent by the client to the server has the client's IP address as the source IP and the server's IP address as the destination IP. The source port is dynamically chosen by the client, and the destination port is typically port 443.
  
- **Flow from the server (outgoing):** Packets sent by the server in response to the client will have the server's IP address as the source IP and the client's IP address as the destination IP. The source port will then be 443 (or another port configured for HTTP/3 on the server), and the destination port will be the one initially chosen by the client.

## Example of a Bidirectional Flow

- **Incoming Flow:**
  - **Source IP Address:** 192.168.1.10 (Client)
  - **Source Port:** 52345 (dynamically chosen by the client)
  - **Destination IP Address:** 203.0.113.5 (HTTP/3 Web Server)
  - **Destination Port:** 443
  - **Protocol:** QUIC/UDP

- **Outgoing Flow:**
  - **Source IP Address:** 203.0.113.5 (HTTP/3 Web Server)
  - **Source Port:** 443
  - **Destination IP Address:** 192.168.1.10 (Client)
  - **Destination Port:** 52345
  - **Protocol:** QUIC/UDP

Thus, the bidirectional flow groups all packets exchanged in both directions (from the client to the server and from the server to the client) under a single logical entity. This grouping allows for coherent and efficient tracking and analysis of communications between a client and an HTTP/3 web server.





### Functionality of the Script

The script performs the following tasks:

1. **Flow Detection**: It identifies and separates each bidirectional flow based on the source IP, destination IP, source port, destination port, and protocol.
2. **UDP Datagram Processing**: For each detected bidirectional flow, the script isolates UDP datagrams.
3. **Datagram Encoding**: The isolated UDP datagrams are then stored and encoded for further analysis.



## Feature Extraction

Features are extracted from bidirectionnal network to analyze and classify the nature of these flows.
Each flow, comprising all packets between a client and an HTTP/3 web server, is examined to extract various features.
Based on these features, class labels are assigned to the flows to categorize them to their nature.

The following features are calculated for each detected bidirectional flow:

| Feature Description | Calculation |
|---------------------|-------------|
| **Proportion of each type of QUIC packet ** | Ratio between the number of UDP datagrams containing a specific packet type and the total number of UDP datagrams generated by a flow. |
| **Proportion of the size of each QUIC packet ** | Ratio of the size (in bytes) of UDP datagrams containing a specific packet type to the total size of all UDP datagrams generated by a flow. |
| **Incoming and outgoing packet size ratio ** | Ratio of the total size of incoming and outgoing packets from the server to the total size of all packets in the flow. This indicates the proportion of data transmitted from the server compared to the overall data size. |
| **Average throughput ** | Average throughput is calculated by dividing the total data size by the total communication time. This metric is calculated for the incoming, outgoing, and bidirectional flows of the detected agents. |
| **Entropy on QUIC packet type and direction ** | Entropy measures the distribution of packets between incoming and outgoing directions for each flow, including the entropy of the types of QUIC packets in each flow. |
| **Packet size variation ** | Average size variation between consecutive packets for each agent. This metric is calculated for the incoming, outgoing, and bidirectional flows of the detected agents. |
| **Packet size standard deviation ** | Standard deviation of packet sizes for each agent. |
| **Statistics related to IAT (mean, standard deviation, skewness, variance) ** | IAT (Inter-Arrival Time) measures the time between consecutive packet arrivals in a data stream. Statistics related to IAT (mean, standard deviation, skewness, variance) are calculated for the incoming, outgoing, and bidirectional flows of each detected agent. |
| **Ratio of the number of QUIC packets in UDP datagrams ** | Ratio between UDP datagrams containing a single QUIC packet and all UDP datagrams associated with each detected agent, and the ratio between UDP datagrams containing multiple QUIC packets and all UDP datagrams associated with each detected agent. |
| **Significant time gap in comparison to the total communication time ** | Count of time gaps detected between each packet using various thresholds relative to the total time of all packets for each identified agent. This metric is calculated for the incoming, outgoing, and bidirectional flows of the detected agents. |

This detailed extraction and feature computation enable comprehensive analysis of the network traffic, aiding in understanding patterns and identifying anomalies.


### Link pcap file

https://drive.google.com/file/d/17yuEqWXWEpyvoxhua5M7BCJnp6zWGPSD/view?usp=drive_link


This link contains network traffic captures (PCAP) illustranting a GET flood attack on a web server using the HTTP/3 protocol (QUIC). In this simulation, several bots send GET requests continuously to the server, generating attack traffic.

### Dataset description

#### The HTTP GET flood class involves a bot establishing a connection with the web server and continuously sending GET requests over this connection throughout the attack. This results in a single bidirectional flow between the bot and the web server during the attack.

#### The Normal Use class involves a bot establishing a connection with the web server and emulating a web client to navigate between the client and the server. This class represents the bidirectional flows of such traffic, reflecting typical web interactions.

#### The QUIC connection flood class involves a bot initiating a connection with the web server, executing a request, and then opening another connection. This means that a single bot initiates multiple bidiretional flows during the attack phase on the web server. This class represents the bidirectional flow generated during this type of attack

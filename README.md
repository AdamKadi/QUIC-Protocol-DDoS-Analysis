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


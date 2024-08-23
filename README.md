# Resources for QUIC Traffic Analysis

This README outlines key aspects of our network traffic analysis, focusing on the target web server, the bidirectional flows studied, the features extracted, and the dataset classes.

## Target Web Server

- **IP Address**: 172.19.0.8
- **Server Type**: NGINX
- **Protocol**: HTTP/3
- **Port**: 443

This web server was the target for both normal traffic emulation and DDoS attack simulations.

## Bidirectional Flows

A bidirectional flow represents the communication between a client and the web server, including packets sent in both directions. For an HTTP/3 web server, the flow captures all exchanged packets between a client’s IP and port and the server’s IP and port.

## Feature Extraction

We extracted several features from each bidirectional flow to analyze and classify network traffic:

- **Proportion of each QUIC packet type**: Ratio of specific packet types to the total in the flow.
- **Proportion of size for each QUIC packet type**: Ratio of specific packet sizes to the total flow size.
- **Incoming vs. outgoing packet size ratio**: Proportion of data sent by the server compared to the total.
- **Average throughput**: Total data size divided by total communication time.
- **Entropy of QUIC packet type and direction**: Measures distribution of packet types and directions.
- **Packet size variation**: Average size difference between consecutive packets.
- **Packet size standard deviation**: Standard deviation of packet sizes.
- **IAT Statistics (mean, std. dev., skewness, variance)**: Time between consecutive packet arrivals.
- **Ratio of QUIC packets in UDP datagrams**: Ratio of single vs. multiple QUIC packets in datagrams.
- **Significant time gap relative to total communication time**: Count of time gaps based on thresholds.

## Dataset Classes

- **HTTP GET Flood**: A bot sends continuous GET requests over a single connection.
- **Normal Use**: A bot simulates typical web browsing behavior.
- **QUIC Connection Flood**: A bot initiates multiple connections without sending data.
- **QUIC Scan**: A bot initiates connections, sends a GET request, and repeats.

The dataset 1 contains two classes: class 0, which includes flows categorized as normal, and class 1, with comprises bidirectional flows as malicious (including Scan, QUIC connect and Get flood).

The dataset 2 contains four classes: class 0, which includes bidirectional flows categorized as normal; class 1, which consists of bidirectional flows of the QUIC Connect type; class 3, which corresponds to bidirectional flows of the Scan type; and class 4, which comprises bidirectional flows of the Get flood type.


## Dataset description

 The HTTP GET flood class involves a bot establishing a connection with the web server and continuously sending GET requests over this connection throughout the attack. This results in a single bidirectional flow between the bot and the web server during the attack.

 The Normal Use class involves a bot establishing a connection with the web server and emulating a web client to navigate between the client and the server. This class represents the bidirectional flows of such traffic, reflecting typical web interactions.

 The QUIC connection flood class involves a bot initiating a connection with the web server, and then opening another connection. This means that a single bot initiates multiple bidiretional flows during the attack phase on the web server. This class represents the bidirectional flow generated during this type of attack.

 The QUIC scan involves a bot initiating a connection with the web server, executing a GET request, and then opening another connection. This means a single bot initiates multiple bidirectional flows, each including a GET request, during the attack phase on the web server. This class represents this bidirectionnal flows generated. 

## Tools and Credits

You can find traffic captures on this link : 
https://www.kaggle.com/datasets/adam357/quic-network-capture-data

The network traffic captures were obtained using tools provided by 6cure, a company specializing in DDoS protection and mitigation 
https://www.6cure.com/en/


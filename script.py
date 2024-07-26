from datetime import datetime
import numpy as np
import pandas as pd 
import pyshark
import time
import binascii
import math
import sys

IP_server = '172.19.0.8'

if len(sys.argv) != 2:
    print(("Usage : python3 "))
    sys.exit(1)

file_path = sys.argv[1]

try:
    with open(file_path, 'r'):
        pass
except FileNotFoundError:
    print(f"Fichier non trouvé: {file_path}")
    sys.exit(1)


file = pyshark.FileCapture(str(file_path), display_filter='quic')

def token_list(liste, tuple_a_verifier):
    """
    Checks if a tuple is in a list.
    
    Args:
        liste (list): List of tuples.
        tuple_a_verifier (tuple): Tuple to check.
    
    Returns:
        bool: True if the tuple is in the list, else False.
    """
    return tuple_a_verifier in liste




def packet_encoding(packet, vector):
    """
    Encodes QUIC packet information into a vector.
    
    Args:
        packet (pyshark.packet): Packet to analyze.
        vector (tuple): Initial vector.
    
    Returns:
        tuple: Updated vector with packet information.
    """
    vector1 = [layer for layer in packet.layers if layer.layer_name == "quic"]
    
    for quic_pkt in vector1:
        try:
            quic_layer = quic_pkt.long_packet_type
            if quic_layer == "0":
                vector = vector[:1] + (1,) + vector[2:]
            elif quic_layer == "1":
                vector = vector[:3] + (1,) + vector[4:]
            elif quic_layer == "2":
                vector = vector[:2] + (1,) + vector[3:]
            elif quic_layer == "3":
                vector = vector[:5] + (1,) + vector[6:]
        except:
            vector = vector[:4] + (1,) + vector[5:]
    
    vector = (len(vector1),) + vector[1:]
    return vector



def it_packets(pcap_file):
    """
    Analyzes packets in a PCAP file and builds a dictionary of packet vectors.
    
    Args:
        pcap_file (str): Path to the PCAP file.
    
    Returns:
        dict: Dictionary of packet vectors.
    """
    cpt = 0
    list_token_users = []
    dicto = {}

    for pkt in pcap_file:
        length = pkt.ip.len
        times = pkt.sniff_time.timestamp()
        packet_vector = (0,0,0,0,0,0)
        cpt += 1

        if pkt['ip'].src == IP_server and pkt['udp'].srcport == '443':
            packet_vector = packet_vector + (1,)
            packet_vector = packet_vector + (length,)
            packet_vector = packet_vector + (times,)
            source_ip = pkt['ip'].dst
            source_port = pkt['udp'].dstport
            new_packet_vector = packet_encoding(pkt, packet_vector)
            var_src = (source_ip, source_port)
            if not token_list(list_token_users, var_src):
                list_token_users.append(var_src)
                dicto[var_src] = [new_packet_vector]
            else:
                dicto[var_src].append(new_packet_vector)
        elif pkt['ip'].dst == IP_server and pkt['udp'].dstport == '443':
            packet_vector = packet_vector + (0,)
            packet_vector = packet_vector + (length,)
            packet_vector = packet_vector + (times,)
            src_ip = pkt['ip'].src
            src_port = pkt['udp'].srcport
            var_dst = (src_ip, src_port)
            new_packet_vector = packet_encoding(pkt, packet_vector)
            if not token_list(list_token_users, var_dst):
                list_token_users.append(var_dst)
                dicto[var_dst] = [new_packet_vector]
            else:
                dicto[var_dst].append(new_packet_vector)
        else:
            print("Nothing")
        
        print(len(dicto))
    
    return dicto






#################################################################### FEATURES #####################################################################


def proportion_of_vector_of_each_packet_types(dico):
    """
    Calculate the proportion of each type of QUIC packet in the given flows.

    Parameters:
    dico (dict): A dictionary where the key is the identifier of a flow, which is a tuple (source IP address, source port),
                 and the value is a list of encoded UDP datagrams for that flow.

    Returns:
    tuple: Five lists containing the proportions of Initial, Handshake, 0-RTT, 1-RTT, and Retry packets respectively.
    """
    liste_Initial = []
    liste_Handshake = []
    liste_0RTT = []
    liste_1RTT = []
    liste_retry = []

    for cle, valeur in dico.items():
        cpt_initial = 0
        cpt_handshake = 0
        cpt_0rtt = 0
        cpt_1rtt = 0
        cpt_retry = 0
        cpt = len(valeur)

        for x in valeur:
            cpt_initial += (x[1] == 1)
            cpt_handshake += (x[2] == 1)
            cpt_0rtt += (x[3] == 1)
            cpt_1rtt += (x[4] == 1)
            cpt_retry += (x[5] == 1)
            # Uncomment the following line if version negotiation packets need to be included
            # cpt_version_negociation += (x[6] == 1)

        var_initial = cpt_initial / cpt
        var_handshake = cpt_handshake / cpt
        var_0rtt = cpt_0rtt / cpt
        var_1rtt = cpt_1rtt / cpt
        var_retry = cpt_retry / cpt
        # Uncomment the following line if version negotiation packets need to be included
        # var_version_negociation = cpt_version_negociation / cpt
        
        liste_Initial.append(var_initial)
        liste_Handshake.append(var_handshake)
        liste_0RTT.append(var_0rtt)
        liste_1RTT.append(var_1rtt)
        liste_retry.append(var_retry)
        # Uncomment the following line if version negotiation packets need to be included
        # liste_version_negociation.append(var_version_negociation)

    # Uncomment the following line if version negotiation packets need to be printed
    # print(liste_version_negociation)

    return liste_Initial, liste_Handshake, liste_0RTT, liste_1RTT, liste_retry



def proportion_of_vector_size_of_each_packet_types(dico):
    """
    This function calculates the proportion of the size of each type of QUIC packet in a flow.

    Parameters:
    dico (dict): A dictionary where the key is the flow identifier (a tuple of source IP address and source port),
                 and the value is a list of encoded UDP datagrams for that flow.

    Returns:
    tuple: Five lists containing the proportion of the size for each type of QUIC packet:
           - Initial
           - Handshake
           - 0-RTT
           - 1-RTT
           - Retry
    """
    
    liste_Initial = []
    liste_Handshake = []
    liste_0RTT = []
    liste_1RTT = []
    liste_retry = []

    for cle, valeur in dico.items():
        cpt = 0
        cpt_initial = 0
        cpt_handshake = 0
        cpt_0rtt = 0
        cpt_1rtt = 0
        cpt_retry = 0

        for x in valeur:
            cpt += int(x[7])
            cpt_initial += int(x[7]) if x[1] == 1 else 0
            cpt_handshake += int(x[7]) if x[2] == 1 else 0
            cpt_0rtt += int(x[7]) if x[3] == 1 else 0
            cpt_1rtt += int(x[7]) if x[4] == 1 else 0
            cpt_retry += int(x[7]) if x[5] == 1 else 0

        var_initial = cpt_initial / cpt if cpt != 0 else 0
        var_handshake = cpt_handshake / cpt if cpt != 0 else 0
        var_0rtt = cpt_0rtt / cpt if cpt != 0 else 0
        var_1rtt = cpt_1rtt / cpt if cpt != 0 else 0
        var_retry = cpt_retry / cpt if cpt != 0 else 0

        liste_Initial.append(var_initial)
        liste_Handshake.append(var_handshake)
        liste_0RTT.append(var_0rtt)
        liste_1RTT.append(var_1rtt)
        liste_retry.append(var_retry)

    return liste_Initial, liste_Handshake, liste_0RTT, liste_1RTT, liste_retry

    
        
def incoming_outgoing_packet_ratio(dico):
    """
    This function calculates the ratio of incoming to outgoing packets for each flow.

    Parameters:
    dico (dict): A dictionary where the key is the flow identifier (a tuple of source IP address and source port),
                 and the value is a list of encoded UDP datagrams for that flow.

    Returns:
    list: A list containing the ratio of incoming to outgoing packets for each flow.
    """
    
    ratio_list = []
    
    for key, value in dico.items():
        incoming_count = 0
        outgoing_count = 0
        
        for packet in value:
            if packet[6] == 0:
                incoming_count += 1
            elif packet[6] == 1:
                outgoing_count += 1
                
        ratio = incoming_count / outgoing_count if outgoing_count != 0 else float('inf')
        ratio_list.append(ratio)
    
    return ratio_list

        
            
def incoming_outgoing_packet_size_ratio(dico):
    """
    This function calculates the ratio of the size of incoming and outgoing packets to the total packet size 
    for each flow, as well as the ratio of incoming to outgoing packet sizes.

    Parameters:
    dico (dict): A dictionary where the key is the flow identifier (a tuple of source IP address and source port),
                 and the value is a list of encoded UDP datagrams for that flow.

    Returns:
    tuple: Three lists containing:
           - The ratio of incoming packet size to total packet size for each flow.
           - The ratio of outgoing packet size to total packet size for each flow.
           - The ratio of incoming packet size to outgoing packet size for each flow.
    """

    liste_incoming = []
    liste_outgoing = []
    liste_ratio = []

    for cle, valeur in dico.items():
        cpt_incoming = 0
        cpt_outgoing = 0
        cpt_all = 0

        for packet in valeur:
            cpt_all += int(packet[7])
            if packet[6] == 0:
                cpt_incoming += int(packet[7])
            elif packet[6] == 1:
                cpt_outgoing += int(packet[7])

        ratio_incoming = cpt_incoming / cpt_all if cpt_all != 0 else 0
        ratio_outgoing = cpt_outgoing / cpt_all if cpt_all != 0 else 0
        ratio_incoming_outgoing = cpt_incoming / cpt_outgoing if cpt_outgoing != 0 else float('inf')

        liste_incoming.append(ratio_incoming)
        liste_outgoing.append(ratio_outgoing)
        liste_ratio.append(ratio_incoming_outgoing)

    return liste_incoming, liste_outgoing, liste_ratio


        

def average_throughput(flow_dict):
    """
    This function calculates the average throughput, average incoming throughput, and average outgoing throughput
    for each flow.

    Parameters:
    flow_dict (dict): A dictionary where the key is the flow identifier (a tuple of source IP address and source port),
                      and the value is a list of encoded UDP datagrams for that flow.

    Returns:
    tuple: Three lists containing:
           - The average throughput for each flow.
           - The average incoming throughput for each flow.
           - The average outgoing throughput for each flow.
    """

    average_list = []
    average_incoming_list = []
    average_outgoing_list = []

    for key, value in flow_dict.items():
        total_size = 0
        incoming_size = 0
        outgoing_size = 0

        first_packet = value[0]
        last_packet = value[-1]

        first_timestamp = first_packet[8]
        last_timestamp = last_packet[8]

        duration = last_timestamp - first_timestamp

        for packet in value:
            total_size += int(packet[7])
            if packet[6] == 0:
                incoming_size += int(packet[7])
            elif packet[6] == 1:
                outgoing_size += int(packet[7])

        average_throughput = total_size / duration if duration != 0 else 0
        average_incoming_throughput = incoming_size / duration if duration != 0 else 0
        average_outgoing_throughput = outgoing_size / duration if duration != 0 else 0

        average_list.append(average_throughput)
        average_incoming_list.append(average_incoming_throughput)
        average_outgoing_list.append(average_outgoing_throughput)

    return average_list, average_incoming_list, average_outgoing_list



def calculate_entropy(flow_dict):
    """
    This function calculates the entropy of the distribution of different QUIC packet types for each flow.

    Parameters:
    flow_dict (dict): A dictionary where the key is the flow identifier (a tuple of source IP address and source port),
                      and the value is a list of encoded UDP datagrams for that flow.

    Returns:
    list: A list containing the entropy value for each flow.
    """

    entropy_list = []
    for key, datagrams in flow_dict.items():
        packet_count = 0
        initial_count = 0
        handshake_count = 0
        zero_RTT_count = 0
        one_RTT_count = 0
        retry_count = 0

        for datagram in datagrams:
            packet_count += 1
            if datagram[1] == 1:
                initial_count += 1
            elif datagram[2] == 1:
                handshake_count += 1
            elif datagram[3] == 1:
                zero_RTT_count += 1
            elif datagram[4] == 1:
                one_RTT_count += 1
            elif datagram[5] == 1:
                retry_count += 1
        
        prop_initial = initial_count / packet_count if packet_count != 0 else 0
        prop_handshake = handshake_count / packet_count if packet_count != 0 else 0
        prop_zero_RTT = zero_RTT_count / packet_count if packet_count != 0 else 0
        prop_one_RTT = one_RTT_count / packet_count if packet_count != 0 else 0
        prop_retry = retry_count / packet_count if packet_count != 0 else 0
        
        entropy_value = 0
        for prop in [prop_initial, prop_handshake, prop_zero_RTT, prop_one_RTT, prop_retry]:
            if prop > 0:
                entropy_value -= prop * math.log2(prop)

        entropy_list.append(entropy_value)

    return entropy_list


def calculate_entropy_direction(flow_dict):
    """
    This function calculates the entropy of the distribution of incoming and outgoing packets for each flow.

    Parameters:
    flow_dict (dict): A dictionary where the key is the flow identifier (a tuple of source IP address and source port),
                      and the value is a list of encoded UDP datagrams for that flow.

    Returns:
    list: A list containing the entropy value for each flow based on the direction (incoming/outgoing) of the packets.
    """

    entropy_list = []
    for key, datagrams in flow_dict.items():
        incoming_count = 0
        outgoing_count = 0
        total_packets = 0

        for datagram in datagrams:
            total_packets += 1
            if datagram[6] == 0:
                incoming_count += 1
            elif datagram[6] == 1:
                outgoing_count += 1
        
        prop_incoming = incoming_count / total_packets if total_packets != 0 else 0
        prop_outgoing = outgoing_count / total_packets if total_packets != 0 else 0

        entropy_value = 0
        for prop in [prop_incoming, prop_outgoing]:
            if prop > 0:
                entropy_value -= prop * math.log2(prop)

        entropy_list.append(entropy_value)

    return entropy_list

def calculate_packet_size_variation(flow_dict):
    """
    This function calculates the average variation in packet size for each flow.

    Parameters:
    flow_dict (dict): A dictionary where the key is the flow identifier (a tuple of source IP address and source port),
                      and the value is a list of encoded UDP datagrams for that flow.

    Returns:
    list: A list containing the average packet size variation for each flow.
    """

    packet_size_variations = []

    for flow_id, packets in flow_dict.items():
        previous_size = None
        size_differences = []

        for packet in packets:
            current_size = int(packet[7])

            if previous_size is not None:
                size_differences.append(abs(current_size - previous_size))

            previous_size = current_size

        # Calculate the average size variation
        average_variation = sum(size_differences) / len(size_differences) if size_differences else 0
        packet_size_variations.append(average_variation)

    return packet_size_variations



def calculate_packet_size_variation_incoming_outgoing(flow_dict):
    """
    This function calculates the average variation in packet size for incoming and outgoing packets separately for each flow.

    Parameters:
    flow_dict (dict): A dictionary where the key is the flow identifier (a tuple of source IP address and source port),
                      and the value is a list of encoded UDP datagrams for that flow.

    Returns:
    tuple: Two lists containing the average packet size variation for incoming and outgoing packets respectively, for each flow.
    """

    variation_incoming_packets = []
    variation_outgoing_packets = []

    for flow_id, packets in flow_dict.items():
        previous_size_incoming = None
        previous_size_outgoing = None
        variation_incoming = []
        variation_outgoing = []

        for packet in packets:
            packet_size = int(packet[7])
            if packet[6] == 0:  # Incoming packet
                if previous_size_incoming is not None:
                    variation_incoming.append(abs(packet_size - previous_size_incoming))
                previous_size_incoming = packet_size
            elif packet[6] == 1:  # Outgoing packet
                if previous_size_outgoing is not None:
                    variation_outgoing.append(abs(packet_size - previous_size_outgoing))
                previous_size_outgoing = packet_size

        # Calculate average size variation for incoming and outgoing packets
        avg_variation_incoming = sum(variation_incoming) / len(variation_incoming) if variation_incoming else 0
        avg_variation_outgoing = sum(variation_outgoing) / len(variation_outgoing) if variation_outgoing else 0

        variation_incoming_packets.append(avg_variation_incoming)
        variation_outgoing_packets.append(avg_variation_outgoing)

    return variation_incoming_packets, variation_outgoing_packets


import math

def calculate_packet_size_std_deviation(flow_dict):
    """
    This function calculates the standard deviation of packet sizes for each flow.

    Parameters:
    flow_dict (dict): A dictionary where the key is the flow identifier (a tuple of source IP address and source port),
                      and the value is a list of encoded UDP datagrams for that flow.

    Returns:
    list: A list containing the standard deviation of packet sizes for each flow.
    """

    std_deviations = []

    for flow_id, packets in flow_dict.items():
        packet_sizes = [int(packet[7]) for packet in packets]

        if len(packet_sizes) > 1:
            mean = sum(packet_sizes) / len(packet_sizes)
            variance = sum((size - mean) ** 2 for size in packet_sizes) / (len(packet_sizes) - 1)
            std_deviation = math.sqrt(variance)
            std_deviations.append(std_deviation)
        else:
            std_deviations.append(0)

    return std_deviations

# Inter arrival time #

def convert_to_datetime(timestamp):
    return datetime.datetime.fromtimestamp(timestamp)


def calcule_IAT(timestamps):
    iats = []
    for i in range(1, len(timestamps)):
        iat = timestamps[i] - timestamps[i-1]
        iats.append(iat)
    return iats


def calculate_iat_statistics(flow_dict):
    """
    This function calculates statistics related to Inter-Arrival Time (IAT) for each flow.

    Parameters:
    flow_dict (dict): A dictionary where the key is the flow identifier (a tuple of source IP address and source port),
                      and the value is a list of encoded UDP datagrams for that flow. Each datagram should include a timestamp.

    Returns:
    tuple: A tuple containing lists of mean, standard deviation, skewness, and variance of IAT for each flow.
    """

    mean_iat_list = []
    std_dev_iat_list = []
    skewness_iat_list = []
    variance_iat_list = []

    for flow_id, packets in flow_dict.items():
        iat_list = []
        total_iat = 0

        # Calculate inter-arrival times (IAT)
        for i in range(1, len(packets)):
            iat = packets[i][8] - packets[i-1][8]  # Assuming timestamp is at index 8
            iat_list.append(iat)
            total_iat += iat

        # Calculate mean IAT
        mean_iat = total_iat / len(packets)
        mean_iat_list.append(mean_iat)

        # Calculate variance of IAT
        variance_iat = sum((iat - mean_iat) ** 2 for iat in iat_list) / len(iat_list)
        variance_iat_list.append(variance_iat)

        # Calculate standard deviation of IAT
        std_dev_iat = math.sqrt(variance_iat)
        std_dev_iat_list.append(std_dev_iat)

        # Calculate skewness of IAT
        skewness_iat = (sum((iat - mean_iat) ** 3 for iat in iat_list) / len(iat_list)) / (std_dev_iat ** 3)
        skewness_iat_list.append(skewness)

    return mean_iat_list, std_dev_iat_list, skewness_iat_list, variance_iat_list


def calculate_iat_incoming_outgoing(flow_dict):
    """
    This function calculates the mean, standard deviation, skewness, and variance of Inter-Arrival Time (IAT)
    for incoming and outgoing packets in each flow.

    Parameters:
    flow_dict (dict): A dictionary where the key is the flow identifier (a tuple of source IP address and source port),
                      and the value is a list of encoded UDP datagrams for that flow. Each datagram should include a timestamp and direction flag.

    Returns:
    tuple: A tuple containing four lists each for incoming and outgoing packets:
           - mean_iat_list_incoming
           - std_dev_iat_list_incoming
           - skewness_iat_list_incoming
           - variance_iat_list_incoming
           - mean_iat_list_outgoing
           - std_dev_iat_list_outgoing
           - skewness_iat_list_outgoing
           - variance_iat_list_outgoing
    """
    mean_iat_list_incoming = []
    std_dev_iat_list_incoming = []
    skewness_iat_list_incoming = []
    variance_iat_list_incoming = []

    mean_iat_list_outgoing = []
    std_dev_iat_list_outgoing = []
    skewness_iat_list_outgoing = []
    variance_iat_list_outgoing = []

    for flow_id, packets in flow_dict.items():
        iat_incoming = []
        iat_outgoing = []
        total_iat_incoming = 0
        total_iat_outgoing = 0

        for i in range(1, len(packets)):
            iat = packets[i][8] - packets[i-1][8]  # Assuming timestamp is at index 8
            if packets[i-1][6] == 0:  # Assuming direction flag is at index 6 (0 for incoming)
                total_iat_incoming += iat
                iat_incoming.append(iat)
            elif packets[i-1][6] == 1:  # Assuming direction flag is at index 6 (1 for outgoing)
                total_iat_outgoing += iat
                iat_outgoing.append(iat)

        if iat_incoming:
            mean_iat_incoming = total_iat_incoming / len(iat_incoming)
            variance_incoming = sum((x - mean_iat_incoming) ** 2 for x in iat_incoming) / len(iat_incoming)
            
            if variance_incoming != 0:
                std_dev_iat_incoming = math.sqrt(variance_incoming)
                skewness_incoming = (sum((x - mean_iat_incoming) ** 3 for x in iat_incoming) / len(iat_incoming)) / (std_dev_iat_incoming ** 3)
            else:
                std_dev_iat_incoming = 0
                skewness_incoming = 0

            mean_iat_list_incoming.append(mean_iat_incoming)
            std_dev_iat_list_incoming.append(std_dev_iat_incoming)
            skewness_iat_list_incoming.append(skewness_incoming)
            variance_iat_list_incoming.append(variance_incoming)
        else:
            mean_iat_list_incoming.append(0)
            std_dev_iat_list_incoming.append(0)
            skewness_iat_list_incoming.append(0)
            variance_iat_list_incoming.append(0)

        if iat_outgoing:
            mean_iat_outgoing = total_iat_outgoing / len(iat_outgoing)
            variance_outgoing = sum((x - mean_iat_outgoing) ** 2 for x in iat_outgoing) / len(iat_outgoing)
            
            if variance_outgoing != 0:
                std_dev_iat_outgoing = math.sqrt(variance_outgoing)
                skewness_outgoing = (sum((x - mean_iat_outgoing) ** 3 for x in iat_outgoing) / len(iat_outgoing)) / (std_dev_iat_outgoing ** 3)
            else:
                std_dev_iat_outgoing = 0
                skewness_outgoing = 0

            mean_iat_list_outgoing.append(mean_iat_outgoing)
            std_dev_iat_list_outgoing.append(std_dev_iat_outgoing)
            skewness_iat_list_outgoing.append(skewness_outgoing)
            variance_iat_list_outgoing.append(variance_outgoing)
        else:
            mean_iat_list_outgoing.append(0)
            std_dev_iat_list_outgoing.append(0)
            skewness_iat_list_outgoing.append(0)
            variance_iat_list_outgoing.append(0)

    return (
        mean_iat_list_incoming, std_dev_iat_list_incoming, skewness_iat_list_incoming, variance_iat_list_incoming,
        mean_iat_list_outgoing, std_dev_iat_list_outgoing, skewness_iat_list_outgoing, variance_iat_list_outgoing
    )



def ratio_nb_quic_packets_in_udp(flow_dict):
    """
    This function calculates the ratio of QUIC packets within UDP datagrams for each flow.

    Parameters:
    flow_dict (dict): A dictionary where the key is the flow identifier (a tuple of source IP address and source port),
                      and the value is a list of encoded UDP datagrams for that flow. Each datagram should include the
                      number of QUIC packets.

    Returns:
    tuple: A tuple containing two lists:
           - ratio_one_quic_packet_list: Ratios of datagrams with exactly one QUIC packet to the total number of datagrams for each flow.
           - ratio_more_than_one_quic_packet_list: Ratios of datagrams with more than one QUIC packet to the total number of datagrams for each flow.
    """
    ratio_one_quic_packet_list = []
    ratio_more_than_one_quic_packet_list = []

    for flow_id, packets in flow_dict.items():
        total_packets = 0
        one_quic_packet_count = 0
        more_than_one_quic_packet_count = 0

        for packet in packets:
            total_packets += 1
            if packet[0] > 1:
                more_than_one_quic_packet_count += 1
            elif packet[0] == 1:
                one_quic_packet_count += 1

        if total_packets > 0:
            ratio_one = one_quic_packet_count / total_packets
            ratio_more_than_one = more_than_one_quic_packet_count / total_packets
        else:
            ratio_one = 0
            ratio_more_than_one = 0

        ratio_one_quic_packet_list.append(ratio_one)
        ratio_more_than_one_quic_packet_list.append(ratio_more_than_one)

    return ratio_one_quic_packet_list, ratio_more_than_one_quic_packet_list


def count_significant_gaps(flow_dict):
    """
    This function calculates the number of significant gaps between packet timestamps for each flow,
    normalized by the session time.

    Parameters:
    flow_dict (dict): A dictionary where the key is the flow identifier (a tuple of source IP address and source port),
                      and the value is a list of encoded UDP datagrams for that flow. Each datagram should include a
                      timestamp at index 8.

    Returns:
    tuple: A tuple containing lists of normalized significant gap counts for various thresholds.
    """
    lower_three_list = []
    lower_three_threshold = 0.0001

    lower_two_list = []
    lower_two_threshold = 0.001

    lower_one_list = []
    lower_one_threshold = 0.01

    lower_list = []
    lower_threshold = 0.1

    list_one = []
    threshold_one = 1

    list_two = []
    threshold_two = 30

    list_three = []
    threshold_three = 60

    list_four = []
    threshold_four = 300

    for flow_id, packets in flow_dict.items():
        timestamps = [packet[8] for packet in packets]  # Retrieve timestamps of each packet
        session_time = timestamps[-1] - timestamps[0]  # Calculate session duration

        count_lower_three = 0
        count_lower_two = 0
        count_lower_one = 0
        count_lower = 0
        count_one = 0
        count_two = 0
        count_three = 0
        count_four = 0

        for i in range(1, len(timestamps)):
            gap = timestamps[i] - timestamps[i - 1]
            if gap > threshold_four:
                count_four += 1
            elif gap > threshold_three:
                count_three += 1
            elif gap > threshold_two:
                count_two += 1
            elif gap > threshold_one:
                count_one += 1
            elif gap > lower_threshold:
                count_lower += 1
            elif gap > lower_one_threshold:
                count_lower_one += 1
            elif gap > lower_two_threshold:
                count_lower_two += 1
            elif gap > lower_three_threshold:
                count_lower_three += 1

        lower_three_list.append(count_lower_three / session_time)
        lower_two_list.append(count_lower_two / session_time)
        lower_one_list.append(count_lower_one / session_time)
        lower_list.append(count_lower / session_time)
        list_one.append(count_one / session_time)
        list_two.append(count_two / session_time)
        list_three.append(count_three / session_time)
        list_four.append(count_four / session_time)

    return lower_three_list, lower_two_list, lower_one_list, lower_list, list_one, list_two, list_three, list_four





#################################################################### FEATURES ######################################################################k



def create_empty_dataframe(input_dict):
    # Récupérer les clés du dictionnaire
    keys = list(input_dict.keys())

    # Créer un DataFrame vide avec les clés comme index et une colonne vide
    df = pd.DataFrame(index=keys, columns=['Proportion of packet of Initial packet types','Proportion of packet of Handshake packet types','Proportion of packet of 0-RTT packet types','Proportion of 1-RTT packet types','Proportion of Retry packet types','Proportion of vector size of Initial packet','Proportion of vector size of Handshake packet','Proportion of vector of vector size of 0-RTT','Proportion of vector size of 1-RTT','Proportion of vector size of Retry packet types','Incoming/Outgoing Packet Ratio','Incoming/Outgoing Packet Size Ratio','Average Throughput','Entropy of packet directions','Entropy of packet types','Incoming data rate','Inbound data rate','Standard deviation packet size','Packet size variation','Packet size variation in','Packet size variation out','Packet size std deviation','mean iat','std_dev_iat', 'skewness_iat', 'variance_iat','mean iat outbound','std_dev_iat_outbound','skewness_iat outbound','variance iat outbound','mean iat incoming','std_dev_iat_incoming','skewness_iat_incoming','variance iat incoming','ratio nb quic packets 1','ratio nb quic packets more 1','global threshold 1','global threshold 2','global threshold 3','global threshold 4','global threshold 5','global threshold 6','global threshold 7','global threshold 8','incoming threshold 1','incoming threshold 2','incoming threshold 3','incoming threshold 4','incoming threshold 5','incoming threshold 6','incoming threshold 7','incoming threshold 8','ongoing threshold 1','ongoing threshold 2','ongoing threshold 3','ongoing threshold 4','ongoing threshold 5','ongoing threshold 6','ongoing threshold 7','ongoing threshold 8'])

    item = proportion_of_vector_of_each_packet_types(input_dict) #5
    print(item)

    df.iloc[:,0] = item[0]
    df.iloc[:,1] = item[1]
    df.iloc[:,2] = item[2]
    df.iloc[:,3] = item[3]
    df.iloc[:,4] = item[4]

    item_1 = proportion_of_vector_size_of_each_packet_types(input_dict) #5

    df.iloc[:,5] = item_1[0]
    df.iloc[:,6] = item_1[1]
    df.iloc[:,7] = item_1[2]
    df.iloc[:,8] = item_1[3]
    df.iloc[:,9] = item_1[4]

    item_2 = incoming_outgoing_packet_ratio(input_dict) #1

    df.iloc[:,10] = item_2

    item_3 = incoming_outgoing_packet_size_ratio(input_dict) #3

    df.iloc[:,10] = item_3[0]
    df.iloc[:,11] = item_3[1]
    df.iloc[:,12] = item_3[2]

    item_4 = average_throughput(input_dict) #3

    df.iloc[:,13] = item_4[0]
    df.iloc[:,14] = item_4[1]
    df.iloc[:,15] = item_4[2]

    item_5 = entropy(input_dict) 

    df.iloc[:,16] = item_5

    item_6 = entropy_direction(input_dict)

    df.iloc[:,17] = item_6

    item_7 = packet_size_variation(input_dict)

    df.iloc[:,18] = item_7

    item_8 = packet_size_variation_incoming_outgoing(input_dict)

    df.iloc[:,19] = item_8[0]
    df.iloc[:,20] = item_8[1]

    item_9 = packet_size_std_deviation(input_dict)

    df.iloc[:,21] = item_9

    item_10 = iat(input_dict)

    df.iloc[:,22] = item_10[0]
    df.iloc[:,23] = item_10[1]
    df.iloc[:,24] = item_10[2]
    df.iloc[:,25] = item_10[3]

    item_11 = iat_incoming(input_dict)

    df.iloc[:,26] = item_11[0]
    df.iloc[:,27] = item_11[1]
    df.iloc[:,28] = item_11[2]
    df.iloc[:,29] = item_11[3]
    df.iloc[:,30] = item_11[4]
    df.iloc[:,31] = item_11[5]
    df.iloc[:,32] = item_11[6]
    df.iloc[:,33] = item_11[7]

    item_12 = ratio_nb_quic_packets_in_udp(input_dict)

    df.iloc[:,34] = item_12[0]
    df.iloc[:,35] = item_12[1]

    item_13 = count_significant_gaps(input_dict)

    df.iloc[:,36] = item_13[0]
    df.iloc[:,37] = item_13[1]
    df.iloc[:,38] = item_13[2]
    df.iloc[:,39] = item_13[3]
    df.iloc[:,40] = item_13[4]
    df.iloc[:,41] = item_13[5]
    df.iloc[:,42] = item_13[6]
    df.iloc[:,43] = item_13[7]

    item_14 = count_significant_gaps_incoming(input_dict)

    df.iloc[:,44] = item_14[0]
    df.iloc[:,45] = item_14[1]
    df.iloc[:,46] = item_14[2]
    df.iloc[:,47] = item_14[3]
    df.iloc[:,48] = item_14[4]
    df.iloc[:,49] = item_14[5]
    df.iloc[:,50] = item_14[6]
    df.iloc[:,51] = item_14[7]


    item_15 = count_significant_gaps_outgoing(input_dict)

    df.iloc[:,52] = item_15[0]
    df.iloc[:,53] = item_15[1]
    df.iloc[:,54] = item_15[2]
    df.iloc[:,55] = item_15[3]
    df.iloc[:,56] = item_15[4]
    df.iloc[:,57] = item_15[5]
    df.iloc[:,58] = item_15[6]
    df.iloc[:,59] = item_15[7]

    df.to_csv('dataset_only_video.csv',index=False)

    return df








if __name__ == '__main__':


    dico_genere = it_packets(file)

    #create_empty_dataframe(dico_genere)

    
    
    

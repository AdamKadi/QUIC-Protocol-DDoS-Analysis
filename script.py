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







def packet_size_std_deviation(dico):
    std_deviations = []

    for _, pile in dico.items():
        packet_sizes = [int(paquet[7]) for paquet in pile]
        if len(packet_sizes) > 1:
            mean = sum(packet_sizes) / len(packet_sizes)
            variance = sum((x - mean) ** 2 for x in packet_sizes) / (len(packet_sizes)-1)
            std_deviation = math.sqrt(variance)
            std_deviations.append(std_deviation)
        else:
            std_deviations.append(0)

    return std_deviations



############################################## Inter arrival time ######

def convert_to_datetime(timestamp):
    return datetime.datetime.fromtimestamp(timestamp)


def calcule_IAT(timestamps):
    iats = []
    for i in range(1, len(timestamps)):
        iat = timestamps[i] - timestamps[i-1]
        iats;append(iat)
    return iats


def iat(dico):
    mean_iat_list = []
    std_dev_iat_list = []
    skewness_iat_list = []
    variance_iat_list = []  # Liste pour stocker les variances

    for key, values in dicto.items():
        liste = []
        cpt = 0
        for i in range(1, len(values)):
            iat = values[i][8] - values[i-1][8]
            cpt += iat
            liste.append(iat)
        
        #Calcule de la moyenne
        mean_iat = cpt / len(values)
        mean_iat_list.append(mean_iat)

        # Calcul de l'écart-type
        variance = sum((x - mean_iat) ** 2 for x in liste) / len(liste)
        variance_iat_list.append(variance)
        
        std_dev_iat = math.sqrt(variance)
        std_dev_iat_list.append(std_dev_iat)

        #Calcul du skewness
        skewness = (sum((x - mean_iat) ** 3 for x in liste) / len(liste)) / (std_dev_iat ** 3)
        skewness_iat_list.append(skewness)

            #print(f"IAT entre {values[i-1][8]} et {values[i][8]} : {iat} secondes")
    return mean_iat_list, std_dev_iat_list, skewness_iat_list, variance_iat_list


def iat_incoming(dico):
    mean_iat_list_0 = []
    std_dev_iat_list_0 = []
    skewness_iat_list_0 = []
    variance_iat_list_0 = []

    mean_iat_list_1 = []
    std_dev_iat_list_1 = []
    skewness_iat_list_1 = []
    variance_iat_list_1 = []

    for key, values in dico.items():
        liste_0 = []
        liste_1 = []
        cpt_0 = 0
        cpt_1 = 0

        for i in range(1, len(values)):
            if values[i-1][6] == 0:
                iat = values[i][8] - values[i-1][8]
                cpt_0 += iat
                liste_0.append(iat)
            elif values[i-1][6] == 1:
                iat = values[i][8] - values[i-1][8]
                cpt_1 += iat
                liste_1.append(iat)
        
        if len(liste_0) > 0:
            mean_iat_0 = cpt_0 / len(liste_0)
            variance_0 = sum((x - mean_iat_0) ** 2 for x in liste_0) / len(liste_0)
            
            if variance_0 != 0:  # Vérification de la variance non nulle
                std_dev_iat_0 = math.sqrt(variance_0)
                skewness_0 = (sum((x - mean_iat_0) ** 3 for x in liste_0) / len(liste_0)) / (std_dev_iat_0 ** 3)
            else:
                std_dev_iat_0 = 0  # Si la variance est nulle, l'écart-type et le skewness sont également nuls
                skewness_0 = 0

            mean_iat_list_0.append(mean_iat_0)
            std_dev_iat_list_0.append(std_dev_iat_0)
            skewness_iat_list_0.append(skewness_0)
            variance_iat_list_0.append(variance_0)

        elif len(liste_0) == 0:
            mean_iat_list_0.append(0)
            std_dev_iat_list_0.append(0)
            skewness_iat_list_0.append(0)
            variance_iat_list_0.append(0)

            
        if len(liste_1) > 0:
            mean_iat_1 = cpt_1 / len(liste_1)
            variance_1 = sum((x - mean_iat_1) ** 2 for x in liste_1) / len(liste_1)
            
            if variance_1 != 0:  # Vérification de la variance non nulle
                
                std_dev_iat_1 = math.sqrt(variance_1)
                skewness_1 = (sum((x - mean_iat_1) ** 3 for x in liste_1) / len(liste_1)) / (std_dev_iat_1 ** 3)
            
            else:
                
                std_dev_iat_1 = 0  # Si la variance est nulle, l'écart-type et le skewness sont également nuls
                skewness_1 = 0

            std_dev_iat_1 = math.sqrt(variance_1)
            skewness_1 = (sum((x - mean_iat_1) ** 3 for x in liste_1) / len(liste_1)) / (std_dev_iat_1 ** 3)

            mean_iat_list_1.append(mean_iat_1)
            std_dev_iat_list_1.append(std_dev_iat_1)
            skewness_iat_list_1.append(skewness_1)
            variance_iat_list_1.append(variance_1)

        elif len(liste_1) == 0:
            mean_iat_list_1.append(0)
            std_dev_iat_list_1.append(0)
            skewness_iat_list_1.append(0)
            variance_iat_list_1.append(0)

        

    return (
        mean_iat_list_0, std_dev_iat_list_0, skewness_iat_list_0, variance_iat_list_0,
        mean_iat_list_1, std_dev_iat_list_1, skewness_iat_list_1, variance_iat_list_1
    )



def ratio_nb_quic_packets_in_udp(dico):
    liste_one = []
    liste_two = []
    for cle, valeur in dico.items():
        cpt_total = 0
        cpt_more_one = 0
        cpt_one = 0
        for pkt in valeur:
            cpt_total += 1
            if pkt[0] > 1:
                cpt_more_one += 1
            elif pkt[0] == 1:
                cpt_one += 1
        res = cpt_one / cpt_total
        res1 = cpt_more_one /cpt_total
        liste_one.append(res)
        liste_two.append(res1)
    return liste_one, liste_two
        



def count_significant_gaps(dico):
    liste_lower_three = []
    threshold_lower_three = 0.0001
    
    liste_lower_two = []
    threshold_lower_two = 0.001
    
    liste_lower_one = []
    threshold_lower_one = 0.01
    
    liste_lower = []
    threshold_lower = 0.1
 
    liste = []
    threshold = 1

    liste_two = []
    threshold_two = 30 

    liste_three = []
    threshold_three = 60

    liste_four = []
    threshold_four = 300


    significant_gaps_count_lower_three = 0
    significant_gaps_count_lower_two = 0
    significant_gaps_count_lower_one = 0
    significant_gaps_count_lower = 0
    significant_gaps_count = 0
    significant_gaps_count_2 = 0
    significant_gaps_count_3 = 0
    significant_gaps_count_4 = 0
    
    for cle, valeur in dico.items():
        timestamp = [packet[8] for packet in valeur] # Récupère les timestamps de chaque paquet
        session_time = timestamp[-1] - timestamp[0]
        #print(session_time)
        for i in range(1, len(timestamp)):
            gap = timestamp[i] - timestamp[i-1]
            if gap > threshold:
                significant_gaps_count += 1
            elif gap > threshold_two:
                significant_gaps_count_2 += 1
            elif gap > threshold_three:
                significant_gaps_count_3 += 1
            elif gap > threshold_four:
                significant_gaps_count_4 += 1
            elif gap > threshold_lower:
                significant_gaps_count_lower += 1
            elif gap > threshold_lower_one:
                significant_gaps_count_lower_one += 1
            elif gap > threshold_lower_two:
                significant_gaps_count_lower_two += 1
            elif gap > threshold_lower_three:
                significant_gaps_count_lower_three += 1

        liste_lower_three.append(significant_gaps_count_lower_three / session_time)
        liste_lower_two.append(significant_gaps_count_lower_two / session_time)
        liste_lower_one.append(significant_gaps_count_lower_one / session_time)
        liste_lower.append(significant_gaps_count_lower / session_time)
        liste.append(significant_gaps_count / session_time)
        liste_two.append(significant_gaps_count_2 / session_time)
        liste_three.append(significant_gaps_count_3 / session_time)
        liste_four.append(significant_gaps_count_4 / session_time)

        

    return liste_lower_three, liste_lower_two, liste_lower_one, liste_lower, liste, liste_two, liste_three, liste_four



def count_significant_gaps_incoming(dico):
    liste_lower_three = []
    threshold_lower_three = 0.0001
    
    liste_lower_two = []
    threshold_lower_two = 0.001
    
    liste_lower_one = []
    threshold_lower_one = 0.01
    
    liste_lower = []
    threshold_lower = 0.1
 
    liste = []
    threshold = 1

    liste_two = []
    threshold_two = 30 

    liste_three = []
    threshold_three = 60

    liste_four = []
    threshold_four = 300


    significant_gaps_count_lower_three = 0
    significant_gaps_count_lower_two = 0
    significant_gaps_count_lower_one = 0
    significant_gaps_count_lower = 0
    significant_gaps_count = 0
    significant_gaps_count_2 = 0
    significant_gaps_count_3 = 0
    significant_gaps_count_4 = 0
    
    for cle, valeur in dico.items():
        timestamp = [packet[8] for packet in valeur if packet[6] == 1] # Récupère les timestamps de chaque paquet
        session_time = valeur[-1][8] -  valeur[0][8]
        
        for i in range(1, len(timestamp)):
            gap = timestamp[i] - timestamp[i-1]
            if gap > threshold:
                significant_gaps_count += 1
            elif gap > threshold_two:
                significant_gaps_count_2 += 1
            elif gap > threshold_three:
                significant_gaps_count_3 += 1
            elif gap > threshold_four:
                significant_gaps_count_4 += 1
            elif gap > threshold_lower:
                significant_gaps_count_lower += 1
            elif gap > threshold_lower_one:
                significant_gaps_count_lower_one += 1
            elif gap > threshold_lower_two:
                significant_gaps_count_lower_two += 1
            elif gap > threshold_lower_three:
                significant_gaps_count_lower_three += 1

        liste_lower_three.append(significant_gaps_count_lower_three / session_time)
        liste_lower_two.append(significant_gaps_count_lower_two / session_time)
        liste_lower_one.append(significant_gaps_count_lower_one / session_time)
        liste_lower.append(significant_gaps_count_lower / session_time)
        liste.append(significant_gaps_count / session_time)
        liste_two.append(significant_gaps_count_2 / session_time)
        liste_three.append(significant_gaps_count_3 / session_time)
        liste_four.append(significant_gaps_count_4 / session_time)

        

    return liste_lower_three, liste_lower_two, liste_lower_one, liste_lower, liste, liste_two, liste_three, liste_four
        


def count_significant_gaps_outgoing(dico):
    liste_lower_three = []
    threshold_lower_three = 0.0001
    
    liste_lower_two = []
    threshold_lower_two = 0.001
    
    liste_lower_one = []
    threshold_lower_one = 0.01
    
    liste_lower = []
    threshold_lower = 0.1
 
    liste = []
    threshold = 1

    liste_two = []
    threshold_two = 30 

    liste_three = []
    threshold_three = 60

    liste_four = []
    threshold_four = 300


    significant_gaps_count_lower_three = 0
    significant_gaps_count_lower_two = 0
    significant_gaps_count_lower_one = 0
    significant_gaps_count_lower = 0
    significant_gaps_count = 0
    significant_gaps_count_2 = 0
    significant_gaps_count_3 = 0
    significant_gaps_count_4 = 0
    
    for cle, valeur in dico.items():
        timestamp = [packet[8] for packet in valeur if packet[6] == 0] # Récupère les timestamps de chaque paquet
        session_time = valeur[-1][8] -  valeur[0][8]
        for i in range(1, len(timestamp)):
            gap = timestamp[i] - timestamp[i-1]
            if gap > threshold:
                significant_gaps_count += 1
            elif gap > threshold_two:
                significant_gaps_count_2 += 1
            elif gap > threshold_three:
                significant_gaps_count_3 += 1
            elif gap > threshold_four:
                significant_gaps_count_4 += 1
            elif gap > threshold_lower:
                significant_gaps_count_lower += 1
            elif gap > threshold_lower_one:
                significant_gaps_count_lower_one += 1
            elif gap > threshold_lower_two:
                significant_gaps_count_lower_two += 1
            elif gap > threshold_lower_three:
                significant_gaps_count_lower_three += 1

        liste_lower_three.append(significant_gaps_count_lower_three / session_time)
        liste_lower_two.append(significant_gaps_count_lower_two / session_time)
        liste_lower_one.append(significant_gaps_count_lower_one / session_time)
        liste_lower.append(significant_gaps_count_lower / session_time)
        liste.append(significant_gaps_count / session_time)
        liste_two.append(significant_gaps_count_2 / session_time)
        liste_three.append(significant_gaps_count_3 / session_time)
        liste_four.append(significant_gaps_count_4 / session_time)

        

    return liste_lower_three, liste_lower_two, liste_lower_one, liste_lower, liste, liste_two, liste_three, liste_four





















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

    
    
    

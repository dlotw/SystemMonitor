__author__ = 'LBJ'

# Packet sniffer in python
# For Linux - Sniffs all incoming and outgoing packets

import socket, sys
from struct import *
import test_psutil

def eth_addr(a):
    """
    Convert a string of 6 characters of ethernet address into a dash separated hex string. Decode MAC address.
    :param a: a string of 6 characters of ethernet address
    :return: a dash separated hex string
    """
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % ((a[0]), (a[1]), (a[2]), (a[3]), (a[4]), (a[5]))
    return b

# create a AF_PACKET type raw socket (thats basically packet level)
# define ETH_P_ALL    0x0003     /* Every packet (be careful!!!) */

def buildSocket():
    try:
        # linux
        # Sniff all data with ethernet header
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        # windows
        # s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        # socket.IPPROTP_IP could be like IPPROTP_TCP IPPROTP_UDP IPPROTP_ICMP

    except socket.error as e:
        print('Socket could not be created. Error Code : {}'.format(e))
        sys.exit()

    return s

def capturePacket(s, res):
    packet = s.recvfrom(65565)
#packet string from tuple
    packet = packet[0]
    # dict for transport layer protocol
    numToProtocol = {6:'TCP', 1:'ICMP', 17:'UDP'}
    portToProcess = test_psutil.mapPortProc()
    # for k, v in portToProcess.items():
    #     print(k, v)

#parse ethernet header
    eth_length = 14

    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])
    res.append(['Length: {}'.format(len(packet))])
    res[-1].append('Destination MAC: {}'.format(eth_addr(packet[0:6])))
    res[-1].append('Source MAC: {}'.format(eth_addr(packet[6:12])))

#Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8:
    #Parse IP header
    #take first 20 characters for the ip header
        ip_header = packet[eth_length:20+eth_length]

    #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        res[-1].append('Version: {}'.format(str(version)))
        res[-1].append('IP Header Length: {}'.format(str(ihl)))
        res[-1].append('TTL: {}'.format(str(ttl)))
        res[-1].append('Source Address: {}'.format(str(s_addr)))
        res[-1].append('Destination Address: {}'.format(str(d_addr)))
        if protocol in numToProtocol:
            res[-1].append('Protocol: {}'.format(numToProtocol[protocol]))
        else:
            res[-1].append('Protocol: {}'.format('-'))

    #TCP protocol
        if protocol == 6:
            # print('TCP protocol')
            t = iph_length + eth_length
            tcp_header = packet[t:t+20]

            #now unpack them
            tcph = unpack('!HHLLBBHHH', tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4

            res[-1].append('Source Port: ' + str(source_port))
            res[-1].append('Dest Port: ' + str(dest_port))
            res[-1].append('Sequence Number: ' + str(sequence))
            res[-1].append('Acknowledgement: ' + str(acknowledgement))
            res[-1].append('TCP header length: ' + str(tcph_length))

            if str(source_port) in portToProcess:
                process = portToProcess[str(source_port)]
                res[-1].append('Process: ' + str(process))

            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size
            res[-1].append('Data Size: ' + str(data_size))

            # get data from the packet
            # data = packet[h_size:].decode()

            # print('Data : ' + data)

        #ICMP Packets
        elif protocol == 1:
            # print('ICMP protocol')
            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u+4]

            #now unpack them
            icmph = unpack('!BBH', icmp_header)

            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]

            res[-1].append('Type: ' + str(icmp_type))
            res[-1].append('Code: ' + str(code))
            res[-1].append('Checksum: ' + str(checksum))

            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size
            res[-1].append('Data Size: ' + str(data_size))

            # get data from the packet
            # data = packet[h_size:].decode()

            # print('Data : ' + data)

        #UDP packets
        elif protocol == 17:
            # print('UDP protocol')
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]

            #now unpack them
            udph = unpack('!HHHH', udp_header)

            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]

            res[-1].append('Source Port: ' + str(source_port))
            res[-1].append('Dest Port: ' + str(dest_port))
            res[-1].append('Length: ' + str(length))
            res[-1].append('Checksum: ' + str(checksum))

            if str(source_port) in portToProcess:
                process = portToProcess[str(source_port)]
                res[-1].append('Process: ' + str(process))

            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size
            res[-1].append('Data Size: ' + str(data_size))

            #get data from the packet
            # data = packet[h_size:].decode()

            # print('Data : ' + data)

        #some other IP packet like IGMP
        else:
            print('Protocol other than TCP/UDP/ICMP')
            res[-1].append('Protocol other than TCP/UDP/ICMP')


def main():
    s = buildSocket()
    res = []
    capturePacket(s, res)
    print(res)

if __name__ == "__main__":
    main()

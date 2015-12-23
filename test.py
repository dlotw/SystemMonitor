__author__ = 'LBJ'

# Packet sniffer in python
# For Linux - Sniffs all incoming and outgoing packets

import socket, sys, psutil
from subprocess import Popen, PIPE
from struct import *
import test_function

#Convert a string of 6 characters of ethernet address into a dash separated hex string. Decode MAC address.
def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % ((a[0]), (a[1]), (a[2]), (a[3]), (a[4]), (a[5]))
    return b

#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003     /* Every packet (be careful!!!) */
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

# def hardwareUsage():
#     cpu_cnt = psutil.cpu_count(logical=True)
#     cpu = psutil.cpu_percent(interval=1, percpu=True)
#
#     mem = psutil.virtual_memory()
#
#     disk_ptt = psutil.disk_partitions()
#     disk = psutil.disk_usage('/')
#     disk_io = psutil.disk_io_counters(perdisk=True)
#
#     network = psutil.net_io_counters()
#     net_io = psutil.net_io_counters(pernic=False)
#     net_interface = psutil.net_if_addrs()
#
#     print("System Usage Logical CPU Count: {} \n".format(cpu_cnt))
#     print("System Usage CPU: {} \n".format(cpu))
#
#     print("System Usage Memory: {} \n".format(mem))
#
#     print("System Usage Dist Partition: {} \n".format(disk_ptt))
#     print("System Usage Disk: {} \n".format(disk))
#     print("System Usage Disk IO: {} \n".format(disk_io))
#
#     print("System Usage Network: {} \n".format(network))
#     print("System Usage Network IO: {} \n".format(net_io))
#     print("System Usage Network Interface: {} \n".format(net_interface))

    #
    # try:
    #     line = "System Usage : {} \n".format(cpu)
    #     f.write(bytes(line, 'UTF-8'))
    #
    #     line = "System Usage : {} \n".format(mem)
    #     f.write(bytes(line, 'UTF-8'))
    #
    #     line = "System Usage : {} \n".format(disk)
    #     f.write(bytes(line, 'UTF-8'))
    #
    #     line = "System Usage : {} \n".format(network)
    #     f.write(bytes(line, 'UTF-8'))
    #
    #     f.write(bytes("################################################################################\n", 'UTF-8'))
    #
    # except Exception as e:
    #     print(e)

def receivePacket(num):

    # receive a packet
    cnt = 0
    while cnt < num:
        cnt += 1
        print(cnt)
        packet = s.recvfrom(65565)
        portToProcess = psDict()
    #packet string from tuple
        packet = packet[0]

    #parse ethernet header
        eth_length = 14

        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])
        print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : '
              + str(eth_protocol))

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

            print(' Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) +
                  ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : '
                  + str(d_addr))

        #TCP protocol
            if protocol == 6:
                print('TCP protocol')
                t = iph_length + eth_length
                tcp_header = packet[t:t+20]

                #now unpack them
                tcph = unpack('!HHLLBBHHH', tcp_header)

                source_port = tcph[0]
                if str(source_port) in portToProcess:
                    process = portToProcess[str(source_port)]
                    flag = True
                else:
                    flag = False
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4
                if flag:
                    print('Process : ' + str(process))
                else:
                    print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) +
                          ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) +
                          ' TCP header length : ' + str(tcph_length))
                h_size = eth_length + iph_length + tcph_length * 4
                data_size = len(packet) - h_size

                #get data from the packet
                # data = packet[h_size:].decode()

                # print('Data : ' + data)

            #ICMP Packets
            elif protocol == 1:
                print('ICMP protocol')
                u = iph_length + eth_length
                icmph_length = 4
                icmp_header = packet[u:u+4]

                #now unpack them :)
                icmph = unpack('!BBH', icmp_header)

                icmp_type = icmph[0]
                code = icmph[1]
                checksum = icmph[2]

                print('Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum))

                h_size = eth_length + iph_length + icmph_length
                data_size = len(packet) - h_size

                #get data from the packet
                # data = packet[h_size:].decode()

                # print('Data : ' + data)

            #UDP packets
            elif protocol == 17:
                print('UDP protocol')
                u = iph_length + eth_length
                udph_length = 8
                udp_header = packet[u:u+8]

                #now unpack them
                udph = unpack('!HHHH', udp_header)

                source_port = udph[0]
                if str(source_port) in portToProcess:
                    process = portToProcess[str(source_port)]
                    flag = True
                else:
                    flag = False
                dest_port = udph[1]
                length = udph[2]
                checksum = udph[3]
                if flag:
                    print('Process : ' + str(process))
                else:
                    print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port)
                            + ' Length : ' + str(length) + ' Checksum : ' + str(checksum))

                h_size = eth_length + iph_length + udph_length
                data_size = len(packet) - h_size

                #get data from the packet
                # data = packet[h_size:].decode()

                # print('Data : ' + data)

            #some other IP packet like IGMP
            else:
                print('Protocol other than TCP/UDP/ICMP')

# def socketToProcess():
#     sockets = psutil.net_connections(kind='inet')
#     for socket in sockets:
#         if socket.pid:
#             print(socket)
#             p = psutil.Process(socket.pid)
#             print(p.name())

# def mapProcess():
#     p1 = Popen(['lsof', '-a', '-p9004', '-i4'], stdout=PIPE)
#     p2 = Popen(["grep", "LISTEN"], stdin=p1.stdout, stdout=PIPE)
#     output = p2.communicate()[0]

# def mapProcess(pid):
#     p = psutil.Process(pid)
#     p.name()
#     print(p.connections())
#     # To filter for listening sockets:
#     output = [x for x in p.connections() if x.status == psutil.CONN_LISTEN]
#     print(output)

def getProcess():
    p1 = Popen(['netstat', '-lnptu'], stdout=PIPE)
    # p2 = Popen(['grep', 'LISTEN'], stdin=p1.stdout, stdout=PIPE)
    output = p1.communicate()[0]
    ret = output.strip()
    ret = ret.decode()
    return ret.split('\n')

def psDict():
    d = {}
    # key: port -- value: process
    ps = getProcess()
    for process in ps:
        port = process.split()[3].split(':')[-1]
        proc = process.split()[-1].split('/')[-1]
        d[port] = proc
    return d

if __name__ == "__main__":
    receivePacket(10)
    test_function.hardware_usage()

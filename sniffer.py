import socket, sys, time, argparse
from struct import *


class Sniffer:
    def __init__(self):
        # argument parser for console arguments
        parser = argparse.ArgumentParser(
            description='A packet sniffer. Collect packets until ctrl+c pressed or after -t seconds ')
        # optimal arguments
        parser.add_argument("-f", "--filename", type=str, help="pcap file name (don't give extension)",
                            default='capture')
        parser.add_argument("-nr", "--noraw", action='store_false', default=True,
                            help="No Raw mode, Stops printing raw packets")
        parser.add_argument("-t", "--time", type=int, default=0, help="Capture time in second")
        # store pares arguments
        self.args = parser.parse_args()
        # initialize stat variables
        self.start_time = time.time()
        self.ip = False
        self.packet_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        # try capture all packets(linux) if not, capture ip packets(windows)
        # windows doesnt support socket.AF_PACKET so fallback to ip packets
        try:
            # create raw packet socket
            self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        except AttributeError:
            # set ip mode true
            self.ip = True
            # get the public network interface
            HOST = socket.gethostbyname(socket.gethostname())

            # create a raw utp socket and bind it to the public interface
            self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self.s.bind((HOST, 0))

            # Include IP headers
            self.s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            # receive all packages
            self.s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except socket.error as e:
            print('Socket could not be created.')
            print('    Error Code : {}'.format(getattr(e, 'errno', '?')))
            print('       Message : {}'.format(e))
            sys.exit()

    # starts capture loop, saves to pcap file and displays packet detail
    def capture_packets(self):
        while True:
            # Receive data from the socket, return value is a pair (bytes, address)
            # max buffer size for packets
            packet = self.s.recvfrom(65565)

            # packet string from tuple
            packet = packet[0]

            print("-------------Packet Start-------------")
            # print raw packet if noraw not given
            if self.args.noraw:
                print('Packet: {}'.format(str(packet)))

            # add packet to pcap file
            self.add_pcap(packet)

            # check if using ip mode or ethernet mode
            if self.ip is not True:
                # parse ethernet header
                eth_length = 14
                # get first 14(eth_length) character from packet
                eth_header = packet[0:eth_length]
                # unpack string big-endian to (6 char, 6 char, unsigned short) format
                eth = unpack('!6s6sH', eth_header)
                # get eth_protocol from unpacked data
                eth_protocol = socket.ntohs(eth[2])
                # create info
                addrinfo = [
                    'Destination MAC: {}'.format(self.mac_addr(packet[0:6])),
                    'Source MAC: {}'.format(self.mac_addr(packet[6:12])),
                    'Protocol: {}'.format(eth_protocol)
                ]
                print('---' + ' '.join(addrinfo))
                # remove ethernet header to parse ip header
                packet = packet[14:]

            self.packet_count += 1

            # take first 20 characters for the ip header
            ip_header = packet[0:20]
            # unpack string big-endian to
            # (skip 8 byte unsigned char(8bit),unsigned char(8bit),skip 2 byte 4 char, 4 char)
            iph = unpack('! 8x B B 2x 4s 4s', ip_header)
            # version and ihl is first 8bit so a char
            version_ihl = packet[0]
            # shift 4 bit right to get version
            version = version_ihl >> 4
            # mask 4 bit to get ihl
            ihl = version_ihl & 0xF
            # calculate header length
            iph_length = ihl * 4
            # get ttl integer
            ttl = iph[0]
            # get protocol integer
            protocol = iph[1]
            # get ip bytes and convert to host byte order
            s_addr = socket.inet_ntoa(iph[2])
            d_addr = socket.inet_ntoa(iph[3])

            headerinfo = [
                'Version: {}'.format(version),
                'IP Header Length: {}'.format(ihl),
                'TTL: {}'.format(ttl),
                'Protocol: {}'.format(protocol),
                'Source Addr: {}'.format(s_addr),
                'Destination Addr: {}'.format(d_addr)]

            # TCP protocol
            if protocol == 6:
                print('---' + ' '.join(headerinfo))
                t = iph_length
                # get 20 characters after ip header
                tcp_header = packet[t:t + 20]

                # unpack string in tcp header format
                tcph = unpack('!HHLLBBHHH', tcp_header)
                self.tcp_count += 1

                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                # shift 4 bits to get length
                tcph_length = doff_reserved >> 4
                # create info
                tcpinfo = [
                    'TCP PACKET',
                    'Source Port: {}'.format(source_port),
                    'Destination Port: {}'.format(dest_port),
                    'Sequence Num: {}'.format(sequence),
                    'Acknowledgement: {}'.format(acknowledgement),
                    'TCP Header Len.: {}'.format(tcph_length),
                ]
                print('---' + ' '.join(tcpinfo))
                # calculate total header size
                h_size = iph_length + tcph_length * 4

                # get data from the packet
                data = packet[h_size:]
                # try to decode plain text data or print hex
                try:
                    print('Data: {}'.format(data.decode('ascii')))
                except:
                    print('Data: {}'.format(str(data)))
            # UDP protocol
            elif protocol == 17:
                print('---' + ' '.join(headerinfo))
                u = iph_length
                udph_length = 8
                # get after 8 character from ip header
                udp_header = packet[u:u + 8]

                # unpack to 4 2bytes
                udph = unpack('!HHHH', udp_header)
                self.udp_count += 1

                source_port = udph[0]
                dest_port = udph[1]
                length = udph[2]
                checksum = udph[3]

                udpinfo = [
                    'UDP PACKET',
                    'Source Port: {}'.format(source_port),
                    'Destination Port: {}'.format(dest_port),
                    'Length: {}'.format(length),
                    'Checksum: {}'.format(checksum)
                ]
                print('---' + ' '.join(udpinfo))

                h_size = iph_length + udph_length

                # get data from the packet

                data = packet[h_size:]

                print('Data: {}'.format(str(data)))
            print("-------------Packet End-------------")
            self.control_time()

    # beatify mac addresses
    def mac_addr(self, a):
        # split address to 6 character
        pieces = (a[i] for i in range(6))
        # format to 00:00:00:00:00:00
        return '{:2x}:{:2x}:{:2x}:{:2x}:{:2x}:{:2x}'.format(*pieces)

    def control_time(self):
        if self.args.time > 0 and ((time.time() - self.start_time) > self.args.time):
            self.exit()
            sys.exit(1)

    def print_stats(self):
        stats = [
            'Captured packets: {}'.format(self.packet_count),
            'TCP Packets: {}'.format(self.tcp_count),
            'UDP Packets: {}'.format(self.udp_count),
            'Total Time: {}'.format(time.time() - self.start_time)
        ]
        print('---' + ' '.join(stats))

    def run(self):
        try:
            # open pcap if ip mode enabled link_type is 101, else 1(ethernet)
            self.open_pcap(self.args.filename + '.pcap', (101 if self.ip else 1))
            # start capturing
            self.capture_packets()
        except KeyboardInterrupt:  # exit on ctrl+c
            self.exit()

    def exit(self):
        # close file
        self.close_pcap()
        # print accumulated stats to screen
        self.print_stats()

    def open_pcap(self, filename, link_type=1):
        # open given filename write mode in binary
        self.pcap_file = open(filename, 'wb')
        # create pcap header and write file
        # header format (https://wiki.wireshark.org/Development/LibpcapFileFormat#Global_Header)
        # (magic_number,version_major,version_minor,thiszone,sigfigs,snaplen,network)
        # python representation
        # (unsigned int(1byte),unsigned short(2byte),unsigned short(2byte),int(4byte),unsigned int(1byte),unsigned int(1byte),unsigned int(1byte))
        self.pcap_file.write(pack('@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type))

    def add_pcap(self, data):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(data)
        # packet header format (https://wiki.wireshark.org/Development/LibpcapFileFormat#Record_.28Packet.29_Header)
        # (ts_sec,ts_usec,incl_len,orig_len)
        # python representation
        # (unsigned int(1byte),unsigned int(1byte),unsigned int(1byte),unsigned int(1byte))
        self.pcap_file.write(pack('@ I I I I', ts_sec, ts_usec, length, length))
        self.pcap_file.write(data)

    def close_pcap(self):
        # close file
        self.pcap_file.close()


if __name__ == '__main__':
    app = Sniffer()
    app.run()

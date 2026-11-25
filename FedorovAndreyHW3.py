import argparse
import socket
import random
import time
from concurrent.futures import ThreadPoolExecutor

def input_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('ip')
    parser.add_argument('--timeout', type=float, default=2.0)
    parser.add_argument('ports', nargs='*')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-g', '--guess', action='store_true')
    return parser.parse_args()

def scan_udp(ip, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    start = time.time()
    sock.sendto(b'\x00', (ip, port))
    
    try:
        _, _ = sock.recvfrom(1024)
        elapsed = (time.time() - start) * 1000
        return ('UDP', port, elapsed)
    except socket.timeout:
        return None
    finally:
        sock.close()

def checksum(msg):
    sum = 0
    for i in range(0, len(msg), 2):
        n = (msg[i] << 8) + (msg[i+1] if i+1 < len(msg) else 0)
        sum += n
    return ~((sum >> 16) + (sum & 0xffff)) & 0xffff

def build_syn(src_ip, dst_ip, src_port, dst_port):
    ip_header = bytearray(20)
    ip_header[0] = 0x45 # формат записи ip и размер ip заголовка
    ip_header[2:4] = (40).to_bytes(2, 'big') # размер сообщения + резерв
    ip_header[8] = 64
    ip_header[9] = 6 # протокол tcp
    ip_header[12:16] = socket.inet_aton(src_ip) #  ip отправителя 
    ip_header[16:20] = socket.inet_aton(dst_ip) # ip получателя

    ip_csum = checksum(bytes(ip_header))
    ip_header[10:12] = ip_csum.to_bytes(2, 'big')
    
    tcp_header = bytearray(20)
    tcp_header[0:2] = src_port.to_bytes(2, 'big')
    tcp_header[2:4] = dst_port.to_bytes(2, 'big')
    tcp_header[12] = 0x50 # длина tcp заголовка 
    tcp_header[13] = 0x02 # SYN
    
    pseudo_header = bytearray(12)
    pseudo_header[0:4] = socket.inet_aton(src_ip) # отправитель
    pseudo_header[4:8] = socket.inet_aton(dst_ip) # gjkexfntkm
    pseudo_header[8] = 0 # резерв
    pseudo_header[9] = 6 # tcp 
    pseudo_header[10:12] = (20).to_bytes(2, 'big') # длина tcp заголовка
    
    tcp_with_pseudo = pseudo_header + tcp_header
    tcp_checksum = checksum(bytes(tcp_with_pseudo))
    tcp_header[16:18] = tcp_checksum.to_bytes(2, 'big')
    
    return bytes(ip_header + tcp_header)

def scan_tcp(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((ip, 80))
        src_ip = s.getsockname()[0]
    finally:
        s.close()

    src_port = random.randint(10000, 60000)

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    syn_pkt = build_syn(src_ip, ip, src_port, port)

    start = time.time()
    send_sock.sendto(syn_pkt, (ip, 0))

    try:
        while True:
            left = timeout - (time.time() - start)
            if left <= 0:
                return None

            recv_sock.settimeout(left)
            pkt, addr = recv_sock.recvfrom(65535)

            if addr[0] != ip:
                continue

            if len(pkt) < 40:
                continue

            ip_header_len = (pkt[0] & 0x0F) * 4
            if len(pkt) < ip_header_len + 20:
                continue

            tcp = pkt[ip_header_len:]

            resp_src_port = int.from_bytes(tcp[0:2], 'big')
            resp_dst_port = int.from_bytes(tcp[2:4], 'big')
            flags = tcp[13]

            if resp_src_port != port:
                continue

            if resp_dst_port != src_port:
                continue

            if (flags & 0x12) == 0x12:
                elapsed = (time.time() - start) * 1000
                return ('TCP', port, elapsed)

            if flags & 0x04:
                return None

    except socket.timeout:
        return None
    finally:
        send_sock.close()
        recv_sock.close()

def parse_ports(ports):
    result = []
    for spec in ports:
        proto, ports_part = spec.split('/')
        for part in ports_part.split(','):
            if '-' in part:
                start, end = part.split('-')
                for port in range(int(start), int(end) + 1):
                    result.append((proto.lower(), port))
            else:
                result.append((proto.lower(), int(part)))
    return result

def guess_proto(port):
    if port in [80, 8080, 8000]:
        return 'HTTP'
    elif port == 53:
        return 'DNS'
    elif port == 7:
        return 'ECHO'
    else:
        return '-'

if __name__ == '__main__':
    args = input_parser()
    ports = parse_ports(args.ports)
    
    def scan_port(proto, port):
        if proto == "udp":
            result = scan_udp(args.ip, port, args.timeout)
        elif proto == "tcp":
            result = scan_tcp(args.ip, port, args.timeout)
        else:
            return None
        
        if result:
            p, port_num, elapsed = result
            if args.verbose and args.guess:
                proto_name = guess_proto(port_num)
                print(f"{p} {port_num} {int(elapsed)}ms {proto_name}")
            elif args.verbose:
                print(f"{p} {port_num} {int(elapsed)}ms")
            elif args.guess:
                proto_name = guess_proto(port_num)
                print(f"{p} {port_num} {proto_name}")
            else:
                print(f"{p} {port_num}")
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(lambda p: scan_port(p[0], p[1]), ports)
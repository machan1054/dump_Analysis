import re

# 書式: 名前, 長さ(バッファ使用時は0), 追加表示在りか?, データ記憶が必要か?, 追加表示フォーマット, データ位置, データ記憶フォーマット
arp = (('HTYPE', 16, True, False, lambda x: 'ETHERNET' if x == '0001' else 'None'),
       ('PTYPE', 16, True, False, lambda x: 'IPv4' if int(x, 16) >= 0x800 else 'None'),
       ('HADDR LEN', 8, True, True, lambda x: (str(int(x, 16)) + ' byte(s)')),
       ('ADDR LEN', 8, True, True, lambda x: (str(int(x, 16)) + ' byte(s)')),
       ('OPER', 16, True, False, lambda x: 'REQUEST' if x =='0001' else 'REPLY' if x == '0002' else 'None'),
       ('S HADDR', 0, True, False, lambda x: haddrTrim(x), lambda x: int(x[1], 16) * 2),
       ('S ADDR', 0, True, False, lambda x: addrTrim(x), lambda x: int(x[2], 16) * 2),
       ('D HADDR', 0, True, False, lambda x: haddrTrim(x), lambda x: int(x[1], 16) * 2),
       ('D ADDR', 0, True, False, lambda x: addrTrim(x), lambda x: int(x[2], 16) * 2))
ipv4 = (('VER', 4, False, False),
        ('HLEN', 4, True, True, lambda x: str(int(x, 16)) + 'line(s)'),
        ('TOS', 8, False, False),
        ('PLEN', 16, True, True, lambda x: str(int(x, 16)) + 'byte(s)'),
        ('ID', 16, False, False),
        (None, 1, False, False),
        ('DF', 1, False, False),
        ('MF', 1, False, False),
        ('FO', 13, False, False),
        ('TTL', 8, False, False),
        ('PROTO', 8, True, True, lambda x: 'ICMP' if x =='01' else 'TCP' if x == '06' else 'UDP' if x == '11' else 'None'),
        ('CKSUM', 16, False, False),
        ('S ADDR', 32, True, False, lambda x: addrTrim(x)),
        ('D ADDR', 32, True, False, lambda x: addrTrim(x)),
        ('OPTION', 0, False, False, None, lambda x: (int(x[1], 16) - 5) * 8),
        ('DATA', 0, False, True, None, lambda x: (int(x[2], 16) - int(x[1], 16) * 4) * 2))
icmp = (('TYPE', 8, True, False, lambda x: 'ECHO MESSAGE' if x =='00' else 'ECHO REPLY MESSAGE' if x == '08' else 'None'),
        ('CODE', 8, False, False),
        ('CHKSUM', 16, False, False),
        ('ID', 16, False, False),
        ('ICMP_SEQ', 16, False, False),
        ('DATA', 0, False, True, None, lambda x: len(x[0]) - 8))
icmp_dum = (('TYPE', 8, True, False, lambda x: 'Destination Unreachable Message' if x =='03' else 'None'),
            ('CODE', 8, True, False, lambda x: 'Network unreachable error' if x == '00' else 'Host unreachable error' if x == '01' else 'None'),
            ('CHKSUM', 16, False, False),
            (None, 8, False, False),
            ('LEN', 8, False, False),
            ('NEXT_MPU', 16, False, False),
            ('DATA', 0, False, True, None, lambda x: len(x[0]) - 8))
udp = (('SPORT', 16, True, True, lambda x: 'UDP/'+ str(int(x, 16)) + ': ' + checkPort(int(x, 16), UDP_PORT)),
       ('DPORT', 16, True, True, lambda x: 'UDP/'+ str(int(x, 16)) + ': ' + checkPort(int(x, 16), UDP_PORT)),
       ('DLEN', 16, True, True, lambda x: (str(int(x, 16)) + ' byte(s)')),
       ('CKSUM', 16, False, False),
       ('DATA', 0, False, True, None, lambda x: int(x[3], 16) * 2))
UDP_PORT = {53: 'Domain Name System (DNS)',
            67: 'Dynamic Host Configuration Protocol (DHCP) server',
            68: 'Dynamic Host Configuration Protocol (DHCP) client',
            123: 'Network Time Protocol (NTP)',
            137: 'NetBIOS Name Service',
            '1023': 'Well-known port',
            '49151': 'Registered port',
            '65536': 'Dynamic, private or ephemeral ports'}
dns = (('ID', 16, False, False),
       ('QR', 1, True, False, lambda x: 'QUERY' if x =='0' else 'RESPONSE' if x == '1' else 'None'),
       ('OPcode', 4, True, False, lambda x: 'STANDARD QUERY' if x =='0000' else 'INVERSE' if x == '0001' else 'SERVER STATUS REQUEST' if x == '0010' else'None'),
       ('AA', 1, True, False, lambda x: 'NON-AUTHORITATIVE' if x =='0' else 'AUTHORITATIVE' if x == '1' else 'None'),
       ('TC', 1, True, False, lambda x: 'Message is not truncated' if x =='0' else 'Message truncated' if x == '1' else 'None'),
       ('RD', 1, False, False),
       ('RA', 1, False, False),
       (None, 3, False, False),
       ('Rcode', 4, True, False, lambda x: 'NoError' if x =='0' else 'FormErr' if x == '1' else 'ServFail' if x == '2' else 'None'),
       ('QUERY COUNT', 16, False, True),
       ('ANSWER COUNT', 16, False, True),
       ('AUTHORICITY COUNT', 16, False, True),
       ('ADDITIONAL COUNT', 16, False, True),
       ('QUERY RECORDS:\n  QNAME', 0, True, False, lambda x: dns_decode(x), lambda x: dns_urllen(x[0][24:])),
       ('  QTYPE', 16, False, False),
       ('  QCLASS', 16, False, False))
tcp = (('SPORT', 16, True, True, lambda x: 'TCP/'+ str(int(x, 16)) + ': ' + checkPort(int(x, 16), TCP_PORT)),
       ('DPORT', 16, True, True, lambda x: 'TCP/'+ str(int(x, 16)) + ': ' + checkPort(int(x, 16), TCP_PORT)),
       ('SEQ_NUM', 32, False, False),
       ('ACK_NUM', 32, False, False),
       ('HLEN', 4, True, True, lambda x: (str(int(x, 16)) + ' line(s)')),
       (None, 3, False, False),
       ('NS', 1, False, False),
       ('CWR', 1, False, False),
       ('ECE', 1, False, False),
       ('URG', 1, False, False),
       ('ACK', 1, False, False),
       ('PSH', 1, False, False),
       ('RST', 1, False, False),
       ('SYN', 1, False, False),
       ('FIN', 1, False, False),
       ('CWND', 16, False, False),
       ('CKSUM', 16, False, False),
       ('URG_POINTER', 16, False, False),
       ('OPTION', 0, False, False, None, lambda x: (int(x[3], 16) - 5) * 8),
       ('DATA', 0, False, True, None, lambda x: len(x[0]) - int(x[3], 16) * 8))
TCP_PORT = {20: 'File Transfer Protocol (FTP) data transfer',
            21: 'File Transfer Protocol (FTP) control',
            22: 'Secure Shell (SSH)',
            23: 'Telnet protocol',
            25: 'Simple Mail Transfer Protocol (SMTP)',
            80: 'Hypertext Transfer Protocol (HTTP)',
            110: 'Post Office Protocol, version 3 (POP3)',
            119: 'Network News Transfer Protocol (NNTP)',
            139: 'NetBIOS Session Service',
            143: 'Internet Message Access Protocol (IMAP)',
            443: 'Hypertext Transfer Protocol over TLS/SSL (HTTPS)',
            '1023': 'Well-known port',
            '49151': 'Registered port',
            '65536': 'Dynamic, private or ephemeral ports'}
telnet = (('DATA', 0, 'split', True, None, lambda x: len(x[0])),)

# 名前，フォーマット，下階層につながるか
mode_list = ({'0806': ('ARP', arp, False), '0800': ('IPv4', ipv4, True)},
            {'01': {'00': ('ICMP', icmp, False), '08': ('ICMP', icmp, False), '03': ('ICMP Destination Unreachable Message', icmp_dum, False)},
             '06': ('TCP', tcp, True), '11': ('UDP', udp, True)},
            {'53': ('DNS', dns, False), '23': ('TELNET', telnet, False)})

def bin_split(x):
    asc_temp = ''
    last_asc = ''
    for i, d in enumerate(x):
        print(d, end='')
        if i % 2 == 1:
            asc = int(last_asc + d, 16)
            if 32 <= asc and asc <= 126:
                asc_temp += chr(asc)
            else:
                asc_temp += '※'
            if i % 4 == 3:
                asc_temp += ' '
        if i % 4 == 3:
            print(' ', end='')
        if i % 32 == 31:
            print('         ' + asc_temp)
            asc_temp = ''
        last_asc = d
    if asc_temp != '':
        print((' ' * (40 - (len(x) % 32 + (len(x) % 32) // 4))) + '         ' + asc_temp)

def dns_urllen(x):
    for i in range(0, len(x)+1, 2):
        if x[i:i+2] == '00':
            return i + 2
    return 0

def dns_decode(x):
    l = 0
    result = ''
    for i in range(0, len(x), 2):
        if l == 0:
            l = int(x[i:i+2], 16)
            if i != 0 and l != 0:
                result += '.'
        else:
            result += chr(int(x[i:i+2], 16))
            l -= 1
    return result

def checkPort(x, portlist):
    if x in portlist:
        return portlist[x]
    last_port = 0
    for port in portlist:
        if type(port) is str:
            if last_port < x and x <= int(port):
                return portlist[port]
            last_port = int(port)
    return 'None'

def haddrTrim(x):
    temp = ''
    haddr_len = len(x)
    for i in range(2, haddr_len + 1, 2):
        temp += x[i - 2:i]
        if i != haddr_len:
            temp += ':'
    return temp


def addrTrim(x):
    temp = ''
    haddr_len = len(x)
    for i in range(2, haddr_len + 1, 2):
        temp += str(int(x[i - 2:i], 16))
        if i != haddr_len:
            temp += '.'
    return temp


def Analysis(data, mode):
    i = 0
    j = 0
    no_data = 1
    if mode is None:
        raise Exception('実装されていないモード')
    temp = [data]
    for fmt in mode:
        base = '0x'
        if fmt[1] == 0:
            n = fmt[5](temp)
            target = data[i : n + i]
            i += n
        elif fmt[1] % 4 == 0 and j == 0:
            target = data[i:(fmt[1] // 4 + i)]
            i += fmt[1] // 4
        else:
            target = bin(int(data[i:fmt[1] // 4 + 2 + i], 16))[2:]
            target = target[j:fmt[1]+j].zfill(fmt[1])
            base = '0b'
            j += fmt[1]
            if(j % 4 == 0):
                i += j // 4
                j = 0
        if fmt[3] is True: # tempに記憶する必要がある時
            temp.append(target)
        if target == '' or fmt[0] is None:
            continue
        no_data = 0
        if len(target) > 46 or fmt[2] == 'split':
            print(fmt[0] + ': ')
            bin_split(target)
        else:
            print('{0}: {2}{1}'.format(fmt[0], target, base), end='')
        if fmt[2] is True: # 追加表示がある時
            print(' -> {}'.format(fmt[4](target)))
        else:
            print()
    if no_data:
        print('No data')
    print()
    return temp


def dumpAnalysis(dump_data):
    data = ''
    for line in dump_data:
        m = re.match(r'\t.+:(.+)\n', line)
        if m:
            # データ部
            data += m.group(1).replace(' ', '')
            print(m.group(1).strip())
        elif data == '':
            # 最初の1行
            print(line.strip())
            typere = re.match(r'.+ethertype.+\(0x(.+)\),.+', line)
            if typere:
                mode = typere.group(1).strip()
        else:
            # 2つ目以降の最初の1行
            print()
            fin = True
            i = 0
            temp = []
            while(fin):
                t_mode = mode_list[i]
                if i == 0:
                    t_mode = t_mode[mode]
                    t_data = data
                elif i == 1:
                    t_mode = t_mode[temp[3]]
                    if type(t_mode) is dict:
                        t_mode = t_mode[temp[4][0:2]]
                    t_data = temp[-1]
                elif i == 2:
                    if str(int(temp[1], 16)) in t_mode:
                        t_mode = t_mode[str(int(temp[1], 16))]
                    else:
                        t_mode = t_mode[str(int(temp[2], 16))]
                    t_data = temp[-1]
                    print(t_data)
                print('mode = ' + t_mode[0])
                temp = Analysis(t_data, t_mode[1])
                fin = t_mode[2]
                i += 1
            print('*------------------------------------------------------*')
            data = ''
            print(line.strip())
            typere = re.match(r'.+ethertype.+\(0x(.+)\),.+', line)
            if typere:
                mode = typere.group(1).strip()

def fileAnalysis(filename):
    with open(filename, mode='r') as f:
        dump_data = f.readlines()
    dumpAnalysis(dump_data)


fileAnalysis('./python/arp_dump.txt')
fileAnalysis('./python/dig_dump.txt')
fileAnalysis('./python/ping_dump.txt')
fileAnalysis('./python/telnet_dump.txt')

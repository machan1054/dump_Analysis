import re

# 書式: 名前, 長さ(バッファ使用時は0), 追加表示在りか?, データ記憶が必要か?, 追加表示フォーマット, データ位置, データ記憶フォーマット
arp = (('HTYPE', 16, 1, 0, lambda x: 'ETHERNET' if x == '0001' else 'None'),
       ('PTYPE', 16, 1, 0, lambda x: 'IPv4' if int(x, 16) >= 0x800 else 'None'),
       ('HADDR LEN', 8, 1, 1, lambda x: (str(int(x, 16)) + ' byte(s)')),
       ('ADDR LEN', 8, 1, 1, lambda x: (str(int(x, 16)) + ' byte(s)')),
       ('OPER', 16, 1, 0, lambda x: 'REQUEST' if x =='0001' else 'REPLY' if x == '0002' else 'None'),
       ('S HADDR', 0, 1, 0, lambda x: haddrTrim(x), lambda x: int(x[1], 16) * 2),
       ('S ADDR', 0, 1, 0, lambda x: addrTrim(x), lambda x: int(x[2], 16) * 2),
       ('D HADDR', 0, 1, 0, lambda x: haddrTrim(x), lambda x: int(x[1], 16) * 2),
       ('D ADDR', 0, 1, 0, lambda x: addrTrim(x), lambda x: int(x[2], 16) * 2))
ipv4 = (('VER', 4, 0, 0),
        ('HLEN', 4, 1, 1, lambda x: str(int(x, 16)) + 'line(s)'),
        ('TOS', 8, 0, 0),
        ('PLEN', 16, 1, 1, lambda x: str(int(x, 16)) + 'byte(s)'),
        ('ID', 16, 0, 0),
        ('FLAGS', 3, 0, 0),
        ('FO', 13, 0, 0),
        ('TTL', 8, 0, 0),
        ('PROTO', 8, 1, 0, lambda x: 'ICMP' if x =='01' else 'TCP' if x == '06' else 'UDP' if x == '11' else 'None'),
        ('CKSUM', 16, 0, 0),
        ('S ADDR', 32, 1, 0, lambda x: addrTrim(x)),
        ('D ADDR', 32, 1, 0, lambda x: addrTrim(x)),
        ('OPTION', 0, 0, 0, None, lambda x: int(x[1], 16) - 5),
        ('DATA', 0, 0, 0, None, lambda x: int(x[2], 16) - int(x[1], 16) * 4))
icmp = (('TYPE', 8, 1, 0, lambda x: 'ECHO MESSAGE' if x =='00' else 'ECHO REPLY MESSAGE' if x == '80' else 'None'),
        ('CODE', 8, 0, 0),
        ('CHKSUM', 16, 0, 0),
        ('ID', 16, 0, 0),
        ('ICMP_SEQ', 16, 0, 0),
        ('DATA', 0, 0, 0, None, lambda x: x[0] - 8))


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
    temp = [len(data)]
    for fmt in mode:
        if fmt[1] % 4 == 0:  # 長さが4で割り切れるか
            if fmt[1] == 0:
                n = fmt[5](temp)
                target = data[i : n + i]
                i += n
            else:
                target = data[i:(fmt[1] // 4 + i)]
                i += fmt[1] // 4
            if target == '':
                continue
            print('{0}: 0x{1}'.format(fmt[0], target), end='')
            if fmt[3] != 0:
                temp.append(target)
            if fmt[2] == 1:
                print(' -> {}'.format(fmt[4](target)))
            else:
                print()
        else:
            j += fmt[1]
            if(j % 4 == 0):
                i += j // 4
                j = 0
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
            if mode == '0806':  # arp
                print('mode=ARP\n')
                temp = Analysis(data, arp)
            elif mode == '0800':  # ipv4
                print('mode=IPv4\n')
                temp = Analysis(data, ipv4)
            else:
                raise Exception('実装されていないモード')
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

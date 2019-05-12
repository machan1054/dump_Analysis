# utils.py
'''dump解析用の関数群'''


def hex2str(x): return str(int(x, 16))
def datalen(x): return len(x[0])


dns_urlList = {}


def bin_split(x):
    '''データをバイナリエディタ風に表示'''
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
            print(' ' * 10 + asc_temp)
            asc_temp = ''
        last_asc = d
    if asc_temp != '':
        print((' ' * (50 - (len(x) % 32 + (len(x) % 32) // 4))) + asc_temp)


def dns_extract(x, bytes):
    global dns_urlList
    result = ''
    for i in range(0, len(x), 2):
        target = int(x[i:i + 2], 16)
        if target >= 0xc0:
            n = int(hex(int(x[i:i + 2], 16) - 0xc0)[2:] + x[i + 2:i + 4], 16)
            for k, v in sorted(dns_urlList.items(), reverse=True):
                if k <= n and n <= k + len(v) / 2:
                    result += dns_extract(v[(n - k) * 2:], -1)[0]
                    if bytes != -1:
                        if not bytes // 8 in dns_urlList:
                            dns_urlList[bytes // 8 + 1] = x[0:i + 4]
                    return (result, i + 4)
            else:
                raise Exception('Cannot find key: {}({})'.format(hex(n), n))
        elif target == 0:
            result += '00'
            if bytes != -1:
                dns_urlList[bytes // 8 + 1] = result
            return (result, i + 2)
        else:
            result += x[i:i + 2]
    raise Exception()


def dns_urllen(x, bytes):
    '''DNSのURLの長さを調べる'''
    return dns_extract(x, bytes)[1]


def dns_decode(x, bytes=-1):
    '''DNSのURLをデコードする'''
    global dns_urlList
    l = 0
    result = ''
    data = dns_extract(x, bytes)[0]
    for i in range(0, len(data), 2):
        target = int(data[i:i + 2], 16)
        if l == 0:
            l = target
            if i != 0 and l != 0:
                result += '.'
        else:
            result += chr(target)
            l -= 1
    return result


def checkPort(x, portlist):
    '''ポート番号が何に使われているのか調べる'''
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
    '''haddrをmacアドレス風に整形する'''
    temp = ''
    haddr_len = len(x)
    for i in range(2, haddr_len + 1, 2):
        temp += x[i - 2:i]
        if i != haddr_len:
            temp += ':'
    return temp


def addrTrim(x):
    '''addrをipアドレス風に整形する'''
    temp = ''
    haddr_len = len(x)
    for i in range(2, haddr_len + 1, 2):
        temp += str(int(x[i - 2:i], 16))
        if i != haddr_len:
            temp += '.'
    return temp

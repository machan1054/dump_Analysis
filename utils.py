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

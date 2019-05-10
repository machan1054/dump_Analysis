import re
from p_formats import *

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

if __name__ == '__main__':
    fileAnalysis('./python/arp_dump.txt')
    fileAnalysis('./python/dig_dump.txt')
    fileAnalysis('./python/ping_dump.txt')
    fileAnalysis('./python/telnet_dump.txt')

import re

from formats import *


def Analysis(data, mode, indent=False, Analyzed=0):
    i = 0
    j = 0
    no_data = 1
    if mode is None:
        raise Exception('実装されていないモード')
    temp = {'DATA': data, 'Analyzed': Analyzed}
    for fmt in mode:
        base = '0x'
        if fmt[1] == 0:  # 長さが不定の場合
            n = fmt[5](temp)
            target = data[i: n + i]
            i += n
            add = n * 4
        elif fmt[1] % 4 == 0 and j == 0:  # 長さが明記かつ16ビットで表せる時
            target = data[i:(fmt[1] // 4 + i)].zfill(fmt[1] // 4)
            i += fmt[1] // 4
            add = fmt[1]
        elif fmt[1] == -1:  # 長さが最後までの時
            target = data[i:]
            i = len(data)
            add = len(data) - temp['Analyzed']
        else:  # 長さが16ビットで表せない時
            target = bin(int(data[i:fmt[1] // 4 + 2 + i], 16))[2:]
            target = target[j:fmt[1] + j].zfill(fmt[1])
            if fmt[1] % 4 == 0:
                target = str(int(target, 2)).zfill(fmt[1] // 4)
            else:
                base = '0b'
            j += fmt[1]
            add = fmt[1]
            if(j % 4 == 0):
                i += j // 4
                j = 0
        if fmt[3] is not False:  # tempに記憶する必要がある時
            temp[fmt[0]] = target
        if target == '' or fmt[0] is None:
            continue
        no_data = 0
        if fmt[2] != 'hide':
            if len(target) > 46 or fmt[2] == 'split':
                print(fmt[0] + ': ')
                bin_split(target)
            else:
                if indent is True:
                    print('    ', end='')
                print('{0}: {2}{1}'.format(fmt[0], target, base), end='')
        if fmt[2] is True or fmt[2] == 'temp':  # 追加表示がある時
            if fmt[2] == 'temp':
                temp['TARGET'] = target
                txt = fmt[4](temp)
            else:
                txt = fmt[4](target)
            if txt is None:
                txt = 'None'
            if txt != '':
                print(' -> ' + txt)
        else:
            print()
        if fmt[3] != 'nocount':
            temp['Analyzed'] += add
    if no_data:
        print('No data')
    print()
    return temp


def typeDecision(line):
    print(line.strip())
    typere = re.match(r'.+ethertype.+\(0x(.+)\),.+', line)
    if typere:
        return typere.group(1).strip()
    elif line != '\n':
        raise Exception('Cannot find ethertype.')


def dumpAnalysis(data, primary_mode):
    fin = True
    i = 0
    temp = {'DATA': data, 'MODE': primary_mode}
    mode_key = 'MODE'
    while(fin):
        if type(mode_key) is tuple:
            for mk in mode_key:
                if temp[mk] in mode_list[i]:
                    t_mode = mode_list[i][temp[mk]]
                    break
            else:
                break
        else:
            if temp[mode_key] in mode_list[i]:
                t_mode = mode_list[i][temp[mode_key]]
            else:
                break
        if type(t_mode) is dict:
            t_mode = t_mode[temp['DATA'][0:2]]
        print('Format: ' + t_mode[0])
        temp = Analysis(temp['DATA'], t_mode[1], Analyzed=0)
        if type(t_mode[3]) is tuple:
            temp2 = temp
            for m in t_mode[3]:
                for j in range(int(temp2[m[2]], 16)):
                    print('{}[{}]:'.format(m[0], j))
                    temp = Analysis(temp['DATA'], m[1], True, temp['Analyzed'])
        if t_mode[2] == False:
            fin = False
        else:
            mode_key = t_mode[2]
        i += 1


def print_dump(dump_data):
    data = ''
    for line in dump_data:
        m = re.match(r'\t.+:(.+)\n', line)
        if m:
            # データ部
            data += m.group(1).replace(' ', '')
            print(m.group(1).strip())
        elif data == '':
            # 最初の1行
            mode = typeDecision(line)
        else:
            # 2つ目以降の最初の1行
            print()
            dumpAnalysis(data, mode)
            print('*------------------------------------------------------*')
            data = ''
            mode = typeDecision(line)


def fileAnalysis(filename):
    with open(filename, mode='r') as f:
        dump_data = f.readlines()
    print_dump(dump_data)


if __name__ == '__main__':
    fileAnalysis('./python/arp_dump.txt')
    fileAnalysis('./python/dig_dump.txt')
    fileAnalysis('./python/ping_dump.txt')
    fileAnalysis('./python/telnet_dump.txt')

from .utils import *
printport_tcp = lambda x: 'TCP/'+ hex2str(x) + ': ' + checkPort(int(x, 16), TCP_PORT)
ascii_ctrl = {0x00:'\0',0x08:'\b',0x09:'\t',0x0A:'\n',0x0D:'\r'}

def print_telnet(x):
    result = '\n'
    for i in range(0, len(x), 2):
        target = int(x[i:i+2], 16)
        if target < 0x20:
            result += ascii_ctrl.get(target, '')
        else:
            result += chr(target)
    print(result)
    return ''

# 書式: 名前, 長さ(バッファ使用時は0), 追加表示在りか?, データ記憶が必要か?, 追加表示フォーマット, データ位置, データ記憶フォーマット
tcp = (('SPORT', 16, True, True, printport_tcp),
       ('DPORT', 16, True, True, printport_tcp),
       ('SEQ_NUM', 32, False, False),
       ('ACK_NUM', 32, False, False),
       ('HLEN', 4, True, True, lambda x: hex2str(x) + ' line(s)'),
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
       ('OPTION', 0, False, False, None, lambda x: (int(x['HLEN'], 16) - 5) * 8),
       ('DATA', -1, False, True, None))
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
telnet = (('DATA', -1, True, False, print_telnet),)

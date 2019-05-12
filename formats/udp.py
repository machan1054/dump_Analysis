from .utils import *
printport_udp = lambda x: 'UDP/'+ hex2str(x) + ': ' + checkPort(int(x, 16), UDP_PORT)
# 書式: 名前, 長さ(バッファ使用時は0), 追加表示在りか?, データ記憶が必要か?, 追加表示フォーマット, データ位置, データ記憶フォーマット
udp = (('SPORT', 16, True, True, printport_udp),
       ('DPORT', 16, True, True, printport_udp),
       ('DLEN', 16, True, True, lambda x: hex2str(x) + ' byte(s)'),
       ('CKSUM', 16, False, False),
       ('DATA', 0, False, True, None, lambda x: int(x['DLEN'], 16) * 2))
UDP_PORT = {53: 'Domain Name System (DNS)',
            67: 'Dynamic Host Configuration Protocol (DHCP) server',
            68: 'Dynamic Host Configuration Protocol (DHCP) client',
            123: 'Network Time Protocol (NTP)',
            137: 'NetBIOS Name Service',
            '1023': 'Well-known port',
            '49151': 'Registered port',
            '65536': 'Dynamic, private or ephemeral ports'}

from .utils import *
# 書式: 名前, 長さ(バッファ使用時は0), 追加表示在りか?, データ記憶が必要か?, 追加表示フォーマット, データ位置, データ記憶フォーマット
ipv4 = (('VER', 4, False, False),
        ('HLEN', 4, True, True, lambda x: hex2str(x) + 'line(s)'),
        ('TOS', 8, False, False),
        ('PLEN', 16, True, True, lambda x: hex2str(x) + 'byte(s)'),
        ('ID', 16, False, False),
        (None, 1, False, False),
        ('DF', 1, False, False),
        ('MF', 1, False, False),
        ('FO', 13, False, False),
        ('TTL', 8, False, False),
        ('PROTO', 8, True, True, {'01':'ICMP','06':'TCP','11':'UDP'}.get),
        ('CKSUM', 16, False, False),
        ('S ADDR', 32, True, False, lambda x: addrTrim(x)),
        ('D ADDR', 32, True, False, lambda x: addrTrim(x)),
        ('OPTION', 0, False, False, None, lambda x: (int(x['HLEN'], 16) - 5) * 8),
        ('DATA', 0, False, True, None, lambda x: int(x['PLEN'], 16) * 2 - int(x['HLEN'], 16) * 8))

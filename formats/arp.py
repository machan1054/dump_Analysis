from .utils import *
# 書式: 名前, 長さ(バッファ使用時は0), 追加表示在りか?, データ記憶が必要か?, 追加表示フォーマット, データ位置, データ記憶フォーマット
arp = (('HTYPE', 16, True, False, {'0001':'ETHERNET'}.get),
       ('PTYPE', 16, True, False, lambda x: 'IPv4' if int(x, 16) >= 0x800 else None),
       ('HADDR LEN', 8, True, True, lambda x: hex2str(x) + ' byte(s)'),
       ('ADDR LEN', 8, True, True, lambda x: hex2str(x) + ' byte(s)'),
       ('OPER', 16, True, False, {'0001':'REQUEST','0002':'REPLY'}.get),
       ('S HADDR', 0, True, False, haddrTrim, lambda x: int(x['HADDR LEN'], 16) * 2),
       ('S ADDR', 0, True, False, addrTrim, lambda x: int(x['ADDR LEN'], 16) * 2),
       ('D HADDR', 0, True, False, haddrTrim, lambda x: int(x['HADDR LEN'], 16) * 2),
       ('D ADDR', 0, True, False, addrTrim, lambda x: int(x['ADDR LEN'], 16) * 2)
       )

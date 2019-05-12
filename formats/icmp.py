from .utils import *
# 書式: 名前, 長さ(バッファ使用時は0), 追加表示在りか?, データ記憶が必要か?, 追加表示フォーマット, データ位置, データ記憶フォーマット
icmp = (('TYPE', 8, True, False, {'00':'ECHO MESSAGE','08':'ECHO REPLY MESSAGE'}.get),
        ('CODE', 8, False, False),
        ('CHKSUM', 16, False, False),
        ('ID', 16, False, False),
        ('ICMP_SEQ', 16, False, False),
        ('DATA', 0, False, True, None, lambda x: len(x['DATA']) - 8))

icmp_dum = (('TYPE', 8, True, False, {'03':'Destination Unreachable Message'}.get),
            ('CODE', 8, True, False, {'00':'Network unreachable error','01':'Host unreachable error'}.get),
            ('CHKSUM', 16, False, False),
            (None, 8, False, False),
            ('LEN', 8, False, False),
            ('NEXT_MPU', 16, False, False),
            ('DATA', 0, False, True, None, lambda x: len(x['DATA']) - 8))

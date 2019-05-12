from .utils import *
opcode_fmt = {'0000':'STANDARD QUERY','0001':'INVERSE','0010':'SERVER STATUS REQUEST'}
tc_fmt = {'0':'Message is not truncated','1':'Message truncated'}
rcode_fmt = {'0':'NoError','1':'FormErr','2':'ServFail'}
recordtype_fmt = {'0001':'A','0002':'NS','0005':'CNAME','0006':'SOA','000c':'PTR',
                  '000f':'MX','0010':'TXT','001c':'AAAA'}

def rdata_extract(x):
    type = int(x['TYPE'], 16)
    if type == 0x01:  # A
        return addrTrim(x['TARGET'])
    elif type in [0x02, 0x05, 0x0c]:
        return dns_decode(x['TARGET'], x['Analyzed'])
    else:
        return '未実装'

# 書式: 名前, 長さ(バッファ使用時は0), 追加表示在りか?, データ記憶が必要か?, 追加表示フォーマット, データ位置, データ記憶フォーマット
dns = (('ID', 16, False, False),
       ('QR', 1, True, False, {'0':'QUERY','1':'RESPONSE'}.get),
       ('OPcode', 4, True, False, opcode_fmt.get),
       ('AA', 1, True, False, {'0':'NON-AUTHORITATIVE','1':'AUTHORITATIVE'}.get),
       ('TC', 1, True, False, tc_fmt.get),
       ('RD', 1, False, False),
       ('RA', 1, False, False),
       (None, 3, False, False),
       ('Rcode', 4, True, False, rcode_fmt.get),
       ('QUERY COUNT', 16, False, True),
       ('ANSWER COUNT', 16, False, True),
       ('AUTHORICITY COUNT', 16, False, True),
       ('ADDITIONAL COUNT', 16, False, True),
       ('DATA', -1, 'hide', 'nocount'))
dns_qr = (('QNAME', 0, True, True, dns_decode, lambda x: dns_urllen(x['DATA'], x['Analyzed'])),
          ('QTYPE', 16, True, False, recordtype_fmt.get),
          ('QCLASS', 16, False, False),
          ('DATA', -1, 'hide', 'nocount'))
dns_ar = (('NAME', 0, True, False, dns_decode, lambda x: dns_urllen(x['DATA'], x['Analyzed'])),
          ('TYPE', 16, True, True, recordtype_fmt.get),
          ('CLASS', 16, False, False),
          ('TTL', 32, False, False),
          ('RDLEN', 16, False, True),
          ('RDATA', 0, 'temp', False, rdata_extract, lambda x: int(x['RDLEN'], 16) *2),
          ('DATA', -1, 'hide', 'nocount'))

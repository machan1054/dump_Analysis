from .arp import *
from .ipv4 import *
from .icmp import *
from .tcp import *
from .udp import *
from .dns import *

dns_fmt = (('QUERY RECORDS', dns_qr, 'QUERY COUNT'),
           ('ANSWER RECORDS', dns_ar, 'ANSWER COUNT'),
           ('AUTHORICITY RECORDS', dns_ar, 'AUTHORICITY COUNT'),
           ('ADDITIONAL RECORDS', dns_ar, 'ADDITIONAL COUNT'))
# 名前，フォーマット，下階層につながるか
mode_list = ({'0806': ('ARP', arp, False, False),
              '0800': ('IPv4', ipv4, 'PROTO', False)},
             {'01': {
                  '00': ('ICMP', icmp, False, False),
                  '08': ('ICMP', icmp, False, False),
                  '03': ('ICMP Destination Unreachable Message', icmp_dum, False, False)},
              '06': ('TCP', tcp, ('SPORT', 'DPORT'), False),
              '11': ('UDP', udp, ('SPORT', 'DPORT'), False)},
             {'0035': ('DNS', dns, False, dns_fmt),
              '0017': ('TELNET', telnet, False, False)})

import re

"""
"""

msg = 'Deny UDP reverse path check from 135.89.112.113 to 32.246.198.2 on interface inside16'

cases = ['(?P<act>Deny)\s(?P<proto>protocol\s[0-9]+)\ssrc\s.+:(?P<sourceAddress>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\sdst\s.+:(?P<dst>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\sby\s.+$', # Deny protocol 47 src outside:180.131.126.136 dst inside:10.195.35.18 by access-group "acl_outside" [0x2b345214, 0x0]
         '(?P<act>Deny)\s(?P<proto>.+)\sreverse\spath\scheck\sfrom\s(?P<sourceAddress>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\sto\s(?P<dst>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\son\s.+$', # Deny UDP reverse path check from 135.89.112.113 to 32.246.198.2 on interface inside16
         '',
        ]

payload = {}
for case in cases:
    match = re.search(case, msg)
    if match:
        for key in match.groupdict():
            payload[key] = match.group(key)
        break

print(payload)


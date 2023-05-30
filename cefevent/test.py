import re

"""
"""

msg = 'Deny inbound UDP from 172.28.96.23/52717 to 10.125.0.5/161 on interface ENGINEERING'

cases = {
         # Deny protocol 47 src outside:180.131.126.136 dst inside:10.195.35.18 by access-group "acl_outside" [0x2b345214, 0x0]
         '1': '(?P<act>Deny)\s(?P<proto>protocol\s[0-9]+)\ssrc\s.+:(?P<sourceAddress>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\sdst\s.+:(?P<dst>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\sby\s.+$',
         # Deny UDP reverse path check from 135.89.112.113 to 32.246.198.2 on interface inside16 
         '2': '(?P<act>Deny)\s(?P<proto>.+)\sreverse\spath\scheck\sfrom\s(?P<sourceAddress>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\sto\s(?P<dst>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\son\s.+$',
         # Deny inbound UDP from 172.28.96.23/52717 to 10.125.0.5/161 on interface ENGINEERING
         '3': '(?P<act>Deny)\s(?P<deviceDirection>inbound)\s(?P<proto>.+)\sfrom\s(?P<sourceAddress>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})/(?P<spt>[0-9]+)\sto\s(?P<dst>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})/(?P<dpt>[0-9]+)\s.+',
        }

payload = {}
for case in cases:
    match = re.search(cases[case], msg)
    if match:
        for key in match.groupdict():
            payload[key] = match.group(key)
        if case == "3":
            payload["deviceDirection"] = payload["deviceDirection"].capitalize() 
        break

print(payload)


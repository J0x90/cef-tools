import re


msg = 'Deny inbound UDP from 172.28.96.23/52717 to 10.125.0.5/161 on interface ENGINEERING'

cases = {
         # Deny UDP reverse path check from 135.89.112.113 to 32.246.198.2 on interface inside16 
         '1': '(?P<act>Deny)\s(?P<proto>.+)\sreverse\spath\scheck\sfrom\s(?P<sourceAddress>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\sto\s(?P<dst>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\son\s.+$',
         # Deny inbound UDP from 172.28.96.23/52717 to 10.125.0.5/161 on interface ENGINEERING
         '2': '(?P<act>Deny)\s(?P<deviceDirection>inbound)\s(?P<proto>.+)\sfrom\s(?P<sourceAddress>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})/(?P<spt>[0-9]+)\sto\s(?P<dst>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})/(?P<dpt>[0-9]+)\s.+',
         # Deny protocol 47 src outside:180.131.126.136 dst inside:10.195.35.18 by access-group "acl_outside" [0x2b345214, 0x0]
         '3': '(?P<act>Deny)\s(?P<proto>protocol\s[0-9]+)\ssrc\s.+:(?P<sourceAddress>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\sdst\s.+:(?P<dst>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\sby\s.+$',
         # Deny tcp src outside:89.248.165.189/45605 dst outside:12.207.186.126/63952 by access-group "acl_outside" [0x2b345214, 0x0]
         '4': '(?P<act>Deny)\s(?P<proto>.+)\ssrc\s.+:(?P<sourceAddress>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})/(?P<spt>[0-9]{1,5})\sdst\s.+:(?P<dst>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})/(?P<dpt>[0-9]{1,5})\s.+$',
         # Deny icmp src ATKEXNET:10.14.115.85 dst inside1:10.95.20.167 (type 3, code 3) by access-group "acl_ATKEXNET" [0xd43ee3b8, 0x0]
         '5': '(?P<act>Deny)\s(?P<proto>icmp)\ssrc\s.+:(?P<sourceAddress>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\sdst\s.+:(?P<dst>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\s.+$',
         # Inbound TCP connection denied from 10.95.26.251/49966 to 192.168.1.21/7680 flags SYN on interface inside1
         '6': '(?P<deviceDirection>Inbound)\s(?P<proto>.+)\sconnection\s(?P<act>.+)\sfrom\s(?P<sourceAddress>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})/(?P<spt>[0-9]{1,5})\sto\s(?P<dst>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})/(?P<dpt>[0-9]{1,5})\s.+$',
         # TCP access denied by ACL from 39.155.22.82/1559 to outside:12.7.224.8/443
         '7': '(?P<proto>.+)\saccess\sdenied\sby\sACL\sfrom\s(?P<sourceAddress>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})/(?P<spt>[0-9]{1,5})\sto\s.+:(?P<dst>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})/(?P<dpt>[0-9]{1,5})',
        }

payload = {}
for case in cases:
    match = re.search(cases[case], msg)
    if match:
        print("case: {}".format(case))
        for key in match.groupdict():
            payload[key] = match.group(key)
        if case == "2":
            payload["deviceDirection"] = payload["deviceDirection"].capitalize() 
        break

print(payload)


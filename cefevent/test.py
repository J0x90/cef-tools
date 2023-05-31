import re

"""
# Deny icmp src ATKEXNET:10.14.115.85 dst inside1:10.95.20.167 (type 3, code 3) by access-group "acl_ATKEXNET" [0xd43ee3b8, 0x0]
elif re.match("Deny\sicmp\ssrc\s", msg)
print("5")
tmp.split(" ")
payload["act"] = tmp[0] # DeviceAction
payload["dst"] = tmp[5].split(":")[1] # DestinationIP
payload["proto"] = tmp[1] # Protocol
payload["sourceAddress"] = tmp[3].split(":")[1] # SourceIP
# Inbound TCP connection denied from 10.95.26.251/49966 to 192.168.1.21/7680 flags SYN on interface inside1
elif re.match("Inbound\s.{,10}\sconnection\sdenied\sfrom\s", msg)
print("6")
tmp.split(" ")
payload["act"] = tmp[3] # DeviceAction
payload["dpt"] = tmp[7].split("/")[1] # DestinationPort
payload["dst"] = tmp[7].split("/")[0] # DestinationIP
payload["proto"] = tmp[1] # Protocol
payload["spt"] = tmp[5].split("/")[1] # SourcePort
payload["sourceAddress"] = tmp[5].split("/")[0] # SourceIP
payload["deviceDirection"] = tmp[0] # CommunicationDirection
# TCP access denied by ACL from 39.155.22.82/1559 to outside:12.7.224.8/443
elif re.match(".{,10}\saccess\sdenied\sby\sACL\sfrom\s", msg)
print("7")
tmp.split(" ")
payload["act"] = tmp[2] # DeviceAction
payload["dpt"] = tmp[8].split("/")[1] # DestinationPort
payload["dst"] = tmp[8].split(":")[1].split("/")[0] # DestinationIP
payload["proto"] = tmp[0] # Protocol
payload["spt"] = tmp[6].split("/")[1] # SourcePort
payload["sourceAddress"] = tmp[6].split("/")[0] # SourceIP
"""

msg = 'Deny tcp src outside:89.248.165.189/45605 dst outside:12.207.186.126/63952 by access-group "acl_outside" [0x2b345214, 0x0]'

cases = {
         # Deny UDP reverse path check from 135.89.112.113 to 32.246.198.2 on interface inside16 
         '1': '(?P<act>Deny)\s(?P<proto>.+)\sreverse\spath\scheck\sfrom\s(?P<sourceAddress>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\sto\s(?P<dst>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\son\s.+$',
         # Deny inbound UDP from 172.28.96.23/52717 to 10.125.0.5/161 on interface ENGINEERING
         '2': '(?P<act>Deny)\s(?P<deviceDirection>inbound)\s(?P<proto>.+)\sfrom\s(?P<sourceAddress>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})/(?P<spt>[0-9]+)\sto\s(?P<dst>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})/(?P<dpt>[0-9]+)\s.+',
         # Deny protocol 47 src outside:180.131.126.136 dst inside:10.195.35.18 by access-group "acl_outside" [0x2b345214, 0x0]
         '3': '(?P<act>Deny)\s(?P<proto>protocol\s[0-9]+)\ssrc\s.+:(?P<sourceAddress>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\sdst\s.+:(?P<dst>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\sby\s.+$',
         # Deny tcp src outside:89.248.165.189/45605 dst outside:12.207.186.126/63952 by access-group "acl_outside" [0x2b345214, 0x0]
         '4': 'Deny\s(?P<proto>.+)\ssrc\s.+:(?P<sourceAddress>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})/(?P<spt>[0-9]{1,5})\sdst\s.+:(?P<dst>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})/(?P<dpt>[0-9]{1,5})\s.+$',
        }

payload = {}
for case in cases:
    match = re.search(cases[case], msg)
    if match:
        for key in match.groupdict():
            payload[key] = match.group(key)
        if case == "1":
            print("case 1")
        if case == "2":
            print("case 2")
            payload["deviceDirection"] = payload["deviceDirection"].capitalize() 
        if case == "3":
            print("case 3")
        if case == "4":
            print("case 4")
        break

print(payload)


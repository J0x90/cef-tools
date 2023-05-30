import re

msg = 'Deny protocol 47 src outside:180.131.126.136 dst inside:10.195.35.18 by access-group "acl_outside" [0x2b345214, 0x0]'

if re.match("Deny\sprotocol\s[0-9]+\ssrc", msg):
    print("match")


import re
import pysyslogclient, datetime, argparse
from event import CEFEvent

client = pysyslogclient.SyslogClientRFC5424("127.0.0.1", "514", proto="UDP")
match_str = "([a-zA-Z]+\s\d{1,2}\s[0-9][0-9]:[0-9][0-9]:[0-9][0-9])\s([^ ]+)\s(%ASA[^: ]+):\s(.+)"
payload = {"deviceVendor": "Cisco", "deviceProduct": "ASA", "DeviceFacility": "local4", "SourceSystem": "OpsManager"}
severity_table = {"1": "High", "2": "High", "3": "Medium", "4": "Medium"}

def send_cef(payload):
    c = CEFEvent()
    #for k, v in payload.items():
    #    print(k)
    #    print(v)
    #    c.set_field(k, v)
    c.set_field('deviceVendor', 'Cisco')
    c.set_field('deviceProduct', 'ASA')
    #c.set_field('dvchost', 'www.mcpforlife.com')
    #message = "This is a test event"
    c.set_field("message", payload["message"])
    c.set_field("DeviceEventClassID", payload["DeviceEventClassID"])
    #c.set_field('sourceAddress', '.168.67.1')
    #c.set_field('sourcePort', 12345)    
    cef_msg = c.build_cef()
    #client.log(message=cef_msg, program="CEF")
    #client.close()

def sys_to_cef(syslog_msg):
    ret = re.findall(match_str, syslog_msg)
    if ret:
        ret = ret[0]
        msg = ret[3]
        dt = ret[0]
        sev = ret[2].split("-")[1]
        payload["DeviceName"] = ret[1]
        payload["Computer"] = ret[1]
        payload["DeviceEventClassID"] = ret[2].split("-")[-1]
        payload["LogSeverity"] = severity_table[sev]
        payload["OriginalLogSeverity"] = sev
        payload["message"] = "{}: {}".format(ret[2], ret[3])
        payload["DeviceAddress"] = ret[1]
        # Deny UDP reverse path check from 135.89.112.113 to 32.246.198.2 on interface inside16
        #if re.match("(Deny)\s(.+6)\s(reverse)\s(path)\s(check)\s(from)\s(.+)\sto\s(.+)\s(on)\s(interface)\s(.+)", msg):
        if re.match("Deny\s.{,10}\sreverse\spath\scheck", msg):
            print("MATCHED!")
            tmp = msg.split(" ")
            payload["DestinationIP"] = tmp[8]
            payload["Protocol"] = tmp[1]
            payload["SourceIP"] = tmp[6]
            payload["RemoteIP"] = tmp[6]
            payload["SimplifiedDeviceAction"] = tmp[0]
        else:
            print("Nothing else to parse")
        print(payload)
        send_cef(payload)
    #print(ret)

msg = "May 23 17:57:43 localhost %ASA-1-106021: Deny UDP reverse path check from 135.89.112.113 to 32.246.198.2 on interface inside16"
#print(msg)

sys_to_cef(msg)


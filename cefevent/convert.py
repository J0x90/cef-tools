import re
import time
import pysyslogclient, datetime, argparse
from event import CEFEvent

client = pysyslogclient.SyslogClientRFC5424("127.0.0.1", "514", proto="UDP")
match_str = "([a-zA-Z]+\s\d{1,2}\s[0-9][0-9]:[0-9][0-9]:[0-9][0-9])\s([^ ]+)\s(%ASA[^: ]+):\s(.+)"
payload = {"deviceVendor": "Cisco", "deviceProduct": "ASA", "deviceFacility": "local4", "SourceSystem": "OpsManager"}
severity_table = {"1": "High", "2": "High", "3": "Medium", "4": "Medium"}

def send_cef(payload, spoof_host):
    c = CEFEvent()
    #for k, v in payload.items():
    #    print(k)
    #    print(v)
    #    c.set_field(k, v)
    c.set_field('deviceVendor', 'Cisco')
    c.set_field('deviceProduct', 'ASA')
    c.set_field("dvchost", payload["dvchost"])
    c.set_field("signatureId", payload["signatureId"])
    c.set_field("severity", payload["severity"])
    #c.set_field("OriginalLogSeverity", payload["OriginalLogSeverity"])
    c.set_field("deviceFacility", payload["deviceFacility"])
    c.set_field("act", payload["act"])
    #c.set_field("simplifiedDeviceAction", payload["simplifiedDeviceAction"])
    c.set_field("sourceAddress", payload["sourceAddress"])
    c.set_field("dst", payload["dst"])
    c.set_field("message", payload["message"])
    c.set_field("rt", payload["rt"])
    c.set_field("proto", payload["proto"])
    #c.set_field("RemoteIP", payload["RemoteIP"])
    #c.set_field("deviceDirection", payload["deviceDirection"])
    cef_msg = c.build_cef()
    print(cef_msg)
    #cef_msg = "CEF:0|Cisco|ASA||106021||High|dvchost=10.28.95.19 deviceFacility=local4 act=Deny src=135.89.112.113 dst=32.246.198.2 msg=%ASA-1-106021: Deny UDP reverse path check from 135.89.112.113 to 32.246.198.2 on interface inside16 rt=5/24/2023 12:46:02 AM proto=UDP OriginalLogSeverity=1 RemoteIP=135.89.112.113"
    client.log(message=cef_msg, program="CEF", hostname=spoof_host)
    client.close()

def sys_to_cef(syslog_msg):
    ret = re.findall(match_str, syslog_msg)
    if ret:
        ret = ret[0]
        msg = ret[3]
        dt = ret[0]
        year = datetime.datetime.now().year
        dt_arr = dt.split(" ")
        fixed_dt = "{} {} {} {}".format(dt_arr[0], dt_arr[1], year, dt_arr[2])
        dt_obj = datetime.datetime.strptime(fixed_dt, "%b %d %Y %H:%M:%S")
        sev = ret[2].split("-")[1]
        payload["dvchost"] = ret[1] # DeviceName
        spoof_host = ret[1]
        payload["signatureId"] = ret[2].split("-")[-1] # DeviceEventClassID
        payload["severity"] = severity_table[sev] # LogSeverity
        #payload["OriginalLogSeverity"] = sev
        payload["message"] = "{}: {}".format(ret[2], ret[3])
        payload["DeviceAddress"] = ret[1]
        #payload["rt"] = time.time() * 1000
        payload["rt"] = datetime.datetime.today().strftime("%-m/%d/%Y %-I:%M:%S %p")
        # Deny UDP reverse path check from 135.89.112.113 to 32.246.198.2 on interface inside16
        #if re.match("(Deny)\s(.+6)\s(reverse)\s(path)\s(check)\s(from)\s(.+)\sto\s(.+)\s(on)\s(interface)\s(.+)", msg):
        if re.match("Deny\s.{,10}\sreverse\spath\scheck", msg):
            #print("MATCHED!")
            tmp = msg.split(" ")
            payload["dst"] = tmp[8]
            payload["proto"] = tmp[1]
            payload["sourceAddress"] = tmp[6]
            #payload["RemoteIP"] = tmp[6]
            payload["act"] = tmp[0] # DeviceAction
            #payload["simplifiedDeviceAction"] = tmp[0]
            #payload["deviceDirection"] = "0"
        else:
            print("Nothing else to parse")
        #print(payload)
        send_cef(payload, spoof_host)
    #print(ret)

msg = "May 23 17:57:43 10.28.95.19 %ASA-1-106021: Deny UDP reverse path check from 135.89.112.113 to 32.246.198.2 on interface inside16"
#print(msg)

sys_to_cef(msg)


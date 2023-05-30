import re
import os
import time
import pysyslogclient, datetime, argparse
from event import CEFEvent

client = pysyslogclient.SyslogClientRFC5424("127.0.0.1", "514", proto="UDP")
match_str = "([a-zA-Z]+\s\d{1,2}\s[0-9][0-9]:[0-9][0-9]:[0-9][0-9])\s([^ ]+)\s(%ASA[^: ]+):\s(.+)"
#payload = {"deviceVendor": "Cisco", "deviceProduct": "ASA", "deviceFacility": "local4", "SourceSystem": "OpsManager"}
payload = {"deviceVendor": "Cisco", "deviceProduct": "ASA", "deviceFacility": "local4"}
severity_table = {"1": "High", "2": "High", "3": "Medium", "4": "Medium"}


def send_cef(payload, spoof_host, syslog_msg):
    c = CEFEvent()
    for k, v in payload.items():
        c.set_field(k, v)
        cef_msg = c.build_cef()
    if(cef_msg):
        pass
        #client.log(message=cef_msg, program="CEF", hostname=spoof_host)
        #client.close()


def sys_to_cef(syslog_msg):
    ret = re.findall(match_str, syslog_msg)
    if ret:
        ret = ret[0]
        msg = ret[3]
        dt = ret[0]
        #msg = 'Deny protocol 47 src outside:180.131.126.136 dst inside:10.195.35.18 by access-group "acl_outside" [0x2b345214, 0x0]'
        year = datetime.datetime.now().year
        dt_arr = dt.split(" ")
        fixed_dt = "{} {} {} {}".format(dt_arr[0], dt_arr[1], year, dt_arr[2])
        dt_obj = datetime.datetime.strptime(fixed_dt, "%b %d %Y %H:%M:%S")
        sev = ret[2].split("-")[1]
        spoof_host = ret[1]
        payload["dvchost"] = ret[1]                                                  # DeviceName
        payload["signatureId"] = ret[2].split("-")[-1]                               # DeviceEventClassID
        payload["severity"] = severity_table[sev]                                    # LogSeverity
        payload["OriginalLogSeverity"] = sev                                         # OriginalLogSeverity
        payload["message"] = "{}: {}".format(ret[2], ret[3])                         # Message
        payload["DeviceAddress"] = ret[1]                                            # Computer
        #payload["rt"] = time.time() * 1000                                           # ReceiptTime
        payload["rt"] = datetime.datetime.today().strftime("%-m/%d/%Y %-I:%M:%S %p") # ReceiptTime
        # Deny UDP reverse path check from 135.89.112.113 to 32.246.198.2 on interface inside16
        print(msg)
        #if re.match("(Deny)\s(.+6)\s(reverse)\s(path)\s(check)\s(from)\s(.+)\sto\s(.+)\s(on)\s(interface)\s(.+)", msg):
        if re.match("Deny\s.{,10}\sreverse\spath\scheck", msg):
            print("1")
            tmp = msg.split(" ")
            payload["dst"] = tmp[8] # DestinationIP
            payload["proto"] = tmp[1]
            payload["sourceAddress"] = tmp[6]
            #payload["RemoteIP"] = tmp[6] # This is automatically added by microsoft
            payload["act"] = tmp[0] # DeviceAction
            #payload["simplifiedDeviceAction"] = tmp[0] # This is automatically added by microsoft
            #payload["deviceDirection"] = "0"
        # Deny inbound UDP from 172.28.96.23/52717 to 10.125.0.5/161 on interface ENGINEERING
        elif re.match("Deny\sinbound\s.{,10}\sfrom", msg):
            print("2")
            tmp = msg.split(" ")
            payload["sourceAddress"] = tmp[4].split("/")[0] # SourceIP
            payload["dst"] = tmp[6].split("/")[0] # DestinationIP
            payload["dpt"] = tmp[6].split("/")[1] # DestinationPort
            payload["proto"] = tmp[2] # Protocol
            payload["act"] = tmp[0] # DeviceAction
            payload["spt"] = tmp[4].split("/")[1] # SourcePort
            payload["deviceDirection"] = tmp[1].capitalize() # CommunicationDirection
            #payload["simplifiedDeviceAction"] = tmp[0] # This is automatically added by microsoft
            #payload["RemoteIP"] = tmp[4].split("/")[0] # This is automatically added by microsoft
            #payload["RemotePort"] = tmp[4].split("/")[1] # This is automatically added by microsoft
        # Deny protocol 47 src outside:180.131.126.136 dst inside:10.195.35.18 by access-group "acl_outside" [0x2b345214, 0x0]
        elif re.match("Deny\sprotocol\s[0-9]+\ssrc", msg):
            print("3")
            tmp = msg.split(" ")
            payload["act"] = tmp[0] # DeviceAction
            payload["dst"] = tmp[6].split(":")[1] # DestinationIP
            payload["proto"] = "protocol {}".format(tmp[2]) # Protocol
            payload["sourceAddress"] = tmp[4].split(":")[1] # SourceIP
        # Deny tcp src outside:89.248.165.189/45605 dst outside:12.207.186.126/63952 by access-group "acl_outside" [0x2b345214, 0x0]
        elif re.match("Deny\s(tcp|udp)\ssrc\s", msg):
            print("4")
            tmp.split(" ")
            payload["act"] = tmp[0] # DeviceAction
            payload["dst"] = tmp[5].split(":")[1].split("/")[0] # DestinationIP
            payload["proto"] = tmp[1] # Protocol
            payload["dpt"] = tmp[5].split(":")[1].split("/")[1] # DestinationPort
            payload["spt"] = tmp[3].split(":")[1].split("/")[1] # SourcePort
            payload["sourceAddress"] = tmp[3].split(":")[1] # SourceIP
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
        else:
            print("No cases matched")
        #print(payload)
        send_cef(payload, spoof_host, syslog_msg)
        print("end")
    #print(ret)


"""
def follow(thefile):
    thefile.seek(0,2)
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line
"""


"""
def follow(f, log_name):
    f.seek(0,2)
    inode = os.fstat(f.fileno()).st_ino
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.1)
            try:
                if os.stat(log_name).st_ino != inode:
                    f.close()
                    f = open(log_name, "r")
                    inode = os.fstat(f.fileno()).st_ino
            except IOError:
                pass
            continue
        yield line
"""


if __name__ == "__main__":
    """
    log_name = "/var/log/asa/asa.log"
    logfile = open(log_name, "r")
    loglines = follow(logfile, log_name)
    for line in loglines:
        line = line.strip()
        sys_to_cef(line)
    """

    file_name = "/var/log/asa/asa.log"
    seek_end = True
    while True: # handle moved/truncated files by allowing to reopen
        with open(file_name) as f:
            if seek_end: # reopened files must not seek end
                f.seek(0, 2)
            while True: # line reading loop
                line = f.readline()
                if not line:
                    try:
                        if f.tell() > os.path.getsize(file_name):
                            # rotation occurred (copytruncate/create)
                            f.close()
                            seek_end = False
                            break
                    except FileNotFoundError:
                        # rotation occurred but new file still not created
                        pass # wait 1 second and retry
                    time.sleep(1)
                e
                    #with open("out.txt", "a") as fw:
                    #    line = line.strip()
                    #    fw.write("{}\n".format(line))
                    sys_to_cef(line)

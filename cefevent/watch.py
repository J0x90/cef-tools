import time

def send_cef(syslog_msg):
    pass


def follow(thefile):
    thefile.seek(0,2)
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

if __name__ == '__main__':
    logfile = open("/var/log/asa/asa.log","r")
    loglines = follow(logfile)
    for line in loglines:
        line = line.strip()
        print(line)
        send_cef(line)


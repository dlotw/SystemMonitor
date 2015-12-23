__author__ = 'LBJ'

import socket
import psutil
import time
import os
import test_function
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM
from contextlib import redirect_stdout

class Monitor(object):

    def __init__(self):
        self.templ = "%-5s %-30s %-30s %-13s %-6s %s"
        self.AD = "-"
        AF_INET6 = getattr(socket, 'AF_INET6', object())
        self.protoMap = {
            (AF_INET, SOCK_STREAM): 'tcp',
            (AF_INET6, SOCK_STREAM): 'tcp6',
            (AF_INET, SOCK_DGRAM): 'udp',
            (AF_INET6, SOCK_DGRAM): 'udp6',
        }
        self.records = set()

    def displayTempl(self):
        print(self.templ % (
        "Proto", "Local address", "Remote address", "Status", "PID",
        "Program name"))

    def getProcName(self):
        procNames = {}
        for p in psutil.process_iter():
            try:
                procNames[p.pid] = p.name()
            except psutil.Error:
                pass
        return procNames

    def getSockets(self):
        procNames = self.getProcName()
        for c in psutil.net_connections(kind='inet'):
            laddr = "%s:%s" % (c.laddr)
            raddr = ""
            if c.raddr:
                raddr = "%s:%s" % (c.raddr)
            self.records.add(
                (
                self.protoMap[(c.family, c.type)],
                laddr,
                raddr or self.AD,
                c.status,
                c.pid or self.AD,
                procNames.get(c.pid, '?')[:15],)
            )

    def getUsage(self):
        test_function.hardware_usage()

    def dumpData(self, path, timeStamp):
        file = os.path.join(path, timeStamp)
        with open(file, "w") as f:
            with redirect_stdout(f):
                self.getUsage()
                self.displayTempl()
                for i in range(len(self.records)):
                    print(self.templ % self.records.pop())

def iterWriter(dir):

    start_time = time.time()
    timeStr = time.strftime("%Y-%m-%d_%H:%M:%S")
    m = Monitor()
    interval = 10

    while True:
        if int(time.time() - start_time) > interval:
            m.dumpData(dir, timeStr+".db")
            start_time = time.time()
            timeStr = time.strftime("%Y-%m-%d_%H:%M:%S")
        else:
            m.getSockets()

def main():
    resDir = r'ResultDB'
    if not os.path.exists(resDir):
        os.makedirs(resDir)
    iterWriter(resDir)

if __name__ == "__main__":
    main()
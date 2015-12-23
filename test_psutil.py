__author__ = 'idap'

import psutil

def socketToProcess():
    sockets = psutil.net_connections(kind='inet')
    for socket in sockets:
        if socket.pid is not None:
            print(socket)
            p = psutil.Process(socket.pid)
            print(p.name())

def mapPortProc():
    portProc = {}
    for c in psutil.net_connections(kind='inet'):
        p = psutil.Process(c.pid)
        portProc[str(c.laddr[1])] = p.name()
    return portProc


if __name__ == "__main__":
    # socketToProcess()
    ret = mapPortProc()
    for k, v in ret.items():
        print(k, v)
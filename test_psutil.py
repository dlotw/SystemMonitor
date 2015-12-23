__author__ = 'idap'

import psutil

def socketToProcess():
    sockets = psutil.net_connections(kind='inet')
    for socket in sockets:
        if socket.pid is not None:
            print(socket)
            p = psutil.Process(socket.pid)
            print(p.name())

if __name__ == "__main__":
    socketToProcess()
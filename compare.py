__author__ = 'LBJ'
import os
import re

def buildBenchMark(wsRes):
    with open(wsRes, 'r') as f:
        lines = f.readlines()
    for i in range(len(lines)):
        line = lines[i].strip().split(',')
        if line[0]

def main():
    resPath = r'ResultDB'
    wsFile = r'wireshark.out'
    idapFile = r'2015-12-29_16:42:31.csv'
    wsRes = os.path.join(resPath, wsFile)
    print(wsRes)
    buildBenchMark(wsRes)

if __name__ == "__main__":
    main()





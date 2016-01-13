__author__ = 'LBJ'
import os
import re
from collections import defaultdict
import csv
import sys


def buildBenchMark(wsRes):
    with open(wsRes, 'r') as f:
        rows = f.readlines()
    for row in rows:
        row = row.strip()
        # print (row)
        frame = re.search(r'(Frame\s)(\d+)(:\s)(\d+)', row)
        if frame:
            # print (frame.group(2))
            frameNo = frame.group(2)
            key = [frame.group(4)]
        else:
            row = row.split(',')
            if re.search(r'Ethernet', row[0]):
                srcMAC = re.search(r'.*\((.*)\)', row[1])
                key.append(srcMAC.group(1))
                dstMAC = re.search(r'.*\((.*)\)', row[2])
                key.append(dstMAC.group(1))
            elif re.search(r'Internet Protocol Version \d', row[0]):
                srcIP = re.search(r'.*\((.*)\)', row[1])
                key.append(srcIP.group(1))
                dstIP = re.search(r'.*\((.*)\)', row[2])
                key.append(dstIP.group(1))
            elif re.search(r'Transmission Control Protocol|User Datagram Protocol', row[0]):
                srcPort = re.search(r'.*\((.*)\)', row[1])
                key.append(srcPort.group(1))
                dstPort = re.search(r'.*\((.*)\)', row[2])
                key.append(dstPort.group(1))
            if len(key) == 7:
                packetFrameTable[tuple(key)].add(int(frameNo))

def matchPattern(patterns, src):
    ret = []
    for patt in patterns:
        match = re.search(patt, src)
        if match:
            start = int(match.end()) + 2
            interval = src[start:].find('\'')
            ret.append(src[start:start+interval])
        else:
            return []
    return ret

def processIDAP(idapRes, newPath):
    keyItems = ['Len', 'SRC MAC', 'DST MAC', 'SRC Address', 'DST Address', 'SRC Port', 'DST Port']
    with open(idapRes, 'r') as f:
        fNew = open(newPath, 'w')
        csvReader = csv.reader(f)
        csvWriter = csv.writer(fNew, delimiter=',')
        try:
            for row in csvReader:
                record = str(row).strip('[]')
                # print (record)
                key = tuple(matchPattern(keyItems, record))
                # print (key)
                value = packetFrameTable[key]
                # print (value)
                row.append(str(list(value)).strip('[]'))
                # print (row)
                csvWriter.writerow(row)
                # print (row)
            # print (len(res))
        except csv.Error as e:
            sys.exit('file %s, line %d, %s' % (idapRes, csvReader.line_num, e))
        finally:
            fNew.close()

def main():
    resPath = r'ResultDB'
    # hard-coded output file name for testing purpose, can be replaced by following code
    # then the output file names should be passed as args in command line
    wsFile = r'wireshark.out'
    idapFile = r'2015-12-29_16:42:31.csv'
    
    # Usage of comapare.py: python3 compare.py [wireshark output] [idap output]
    # wsRes = os.path.join(resPath, sys.argv[1])
    # idapRes = os.path.join(resPath, sys.argv[2])
    
    newFile = idapFile.strip('.csv') + '_compare.csv'
    # global variable, a hashmap called packetFrameTable, key-value pair
    # key: packet info parsed from header
    # including 'Len', 'SRC MAC', 'DST MAC', 'SRC Address', 'DST Address', 'SRC Port', 'DST Port'
    # value: # of Frame in wireshark output
    global packetFrameTable
    packetFrameTable = defaultdict(set)
    wsRes = os.path.join(resPath, wsFile)
    idapRes = os.path.join(resPath, idapFile)
    newPath = os.path.join(resPath, newFile)

    buildBenchMark(wsRes)
    processIDAP(idapRes, newPath)

    # for k,v in packetFrameTable.items():
    #    print (k)
    #    print (type(v), v)

if __name__ == "__main__":
    main()

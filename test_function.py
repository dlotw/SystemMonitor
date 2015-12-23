#!/usr/bin/env python
# coding=utf-8

import psutil
import disk_usage
import meminfo
import free
import ifconfig
import netstat
import who

def cpu_usage():
    cpu_cnt = psutil.cpu_count(logical=True)
    cpu_pct = psutil.cpu_percent(interval=1, percpu=True)
    print("Logical CPU Count: {} \n".format(cpu_cnt))
    print("CPU Usage Percentage: {} \n".format(cpu_pct))

def hardware_usage():
    spliter = '#'*80

    print("%s" % spliter)
    print("DISK INFO")
    print("%s" % spliter)
    disk_usage.main()

    print("%s" % spliter)
    print("MEMERY INFO")
    print("%s" % spliter)
    free.main()
    meminfo.main()

    print("%s" % spliter)
    print("NETWORK INFO")
    print("%s" % spliter)
    ifconfig.main()
    # netstat.main()

    print("%s" % spliter)
    print("USER INFO")
    print("%s" % spliter)
    who.main()

    print("%s" % spliter)
    print("CPU INFO")
    print("%s" % spliter)
    cpu_usage()

def main():
    hardware_usage()

if __name__ == '__main__':
    main()

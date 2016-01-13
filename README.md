# SystemMonitor

## monitor.py

### Methods in Monitor Class


	displayTempl(): print template for displaying packet
	getProcName(): build process pid to name hash map, needed for each state-capture of monitored system
	getSockets(): capture all the network connections at one time and process to populate packet info
	cachePacket(): receive packet through socket and parse header to gather information about this packet
	getUsage(): collect hardware usage
	dumpData(): create DB file for a that period of time. Dump all cached packet info and hardware usage from memory. Then free memory

### Driver Program


	Inside a while loop:
	If current system time - start time > interval (adjusted by system administrator):
		1. dump data from memory to DB files
		2. free memory
		3. set start time to current time
	else:
		continue monitoring network traffic and cache results in memory

## test_packet.py

### helper functions to analyse network packet

	eth_addr():  convert 6 byte string of ethernet address into a dash separated hex string to decode MAC address
	buildSocket(): create socket to sniffer all in/out network packet
	capturePacket(): receive packet through previous created socket, parse header and store packet info

## ResultDB
Results for monitoring, separate DB files for each period of time (interval could be adjusted)

### Benchmark using WireShark
In order to validate our networking monitor features, we build benchmark using open-source software called WireShark, which is widely used amongst network-related projects in both industry and researches.

We run our Monitor and WireShark simultaneously, gathering result file and store them in ResultDB directory. Then we build a script to compare those 2 results and try to find possible matches in WireShark for every packet captured by our Monitor.

### compare.py

Run this result comparing script by:
`python3 compare.py [WireShark output file] [our monitor output file]`

Basically, when reading WireShark output file, it would build a a hashmap called packetFrameTable. Using regular expression to parse the file, we can have the following key-value pair in packetFrameTable.

    key: packet info parsed from header, including 'Len', 'SRC MAC', 'DST MAC', 'SRC Address', 'DST Address', 'SRC Port' and 'DST Port'
    value: Frame # in WireShark output

With this hashmap, we can find all possible matched packet frame in WireShark for a specific packet captured by our monitor in constant time. So while reading our monitor output file, we find matched frames on the fly and write the original packet info together with the matched frames to a new file. By default, this new file is named by adding '_compare' to the existing output of our monitor.

## Utility Functions
All other .py files are implemented to build separate modules for monitoring different system usages, such as disk, memory, network, user, cpu, etc.

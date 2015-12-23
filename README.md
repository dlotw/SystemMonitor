# SystemMonitor

## list_sockets.py

### Methods in Monitor Class


	displayTempl(): print template for displaying packet
	getProcName(): build process pid to name hash map, needed for each state-capture of monitored system
	getSockets(): capture all the network connections at one time and process to populate packet info
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

## ResultDB
Results for monitoring, separate DB files for each period of time (interval could be adjusted)

## Utility Functions
All other .py files are implemented to build separate modules for monitoring different system usages, such as disk, memory, network, user, cpu, etc.

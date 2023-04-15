import lib.icmp_common as icmp_common

from scapy.all import *
from time import sleep


class icmpSend(icmp_common.absurdIcmp):
    def __init__(self, destination: str, filename: str):

        self.destination = destination
        self.filename = filename
        self.pkts = []

    def start(self):

        if self.destination == "127.0.0.1":
            conf.L3socket = L3RawSocket

        print("Sending start bits")
        sr(IP(dst=self.destination) / self.start_icmp, retry=3, timeout=1)
        sleep(1)
        print("Sending filename")
        self.send_filename()
        print("Sending file")
        self.transmit_file()
        print("Sending verification")
        self.send_verification()
        sleep(1)
        print("Sending stop bits")
        sr(IP(dst=self.destination) / self.stop_icmp, retry=3, timeout=1)

    def send_generic_str(self, destination: str, text: str):
        """
        sends generic ascii strings encoded in the sequence number
        """

        bytes = text.encode("ascii")
        id_counter = self.low_identifier
        pkts = []

        for i in range(0, len(bytes), 2):

            if id_counter > self.max_id:

                # since we send 15 packets at a time pkts should be empty when starting a new chunk
                if len(pkts) == 0:
                    self.start_next_chunk(destination)
                else:
                    raise ValueError(
                        "Tried to start next chunk with a non-empty packet buffer"
                    )

            sequence = int.from_bytes(bytes[i : i + 2], "big")
            pkts.append(IP(dst=destination) / ICMP(id=id_counter, seq=sequence))

            if len(pkts) == 15:
                sr(pkts, retry=3, timeout=1)
                print(f"sent 15 packets last id is {id_counter}")
                pkts = []

            id_counter += 1

        if len(pkts) > 0:
            sr(pkts, retry=3, timeout=1)
            print(f"sent {len(pkts)} last id is {id_counter}")

    def send_filename(self):

        sr(IP(dst=self.destination) / self.start_filename_icmp, retry=3, timeout=1)
        self.send_generic_str(self.destination, self.filename)
        sr(IP(dst=self.destination) / self.stop_filename_icmp, retry=3, timeout=1)

    def send_verification(self):
        """
        after sending we should verify our file was transmitted correctly.

        we do this by first sending a control code to notify the receiver
        we are starting the verification process, then we send the sha256
        checksum encoded as sequence numbers and finally we send a control
        code stopping the verification process.

        as built we don't have a way of knowing if the transfer failed from
        the senders end, so any error handling is up to the receipent for
        files sent in clear text this might still result in useful data
        """

        digest = self.hash_file(self.filename)
        print(type(digest))
        print(digest)
        sr(IP(dst=self.destination) / self.start_verify_icmp, retry=3, timeout=1)

        id_counter = 1
        for i in range(0, len(digest), 2):
            sr(
                IP(dst=self.destination)
                / ICMP(id=id_counter, seq=int.from_bytes(digest[i : i + 2], "big"))
            )
            id_counter += 1

        sr(IP(dst=self.destination) / self.stop_verify_icmp, retry=3, timeout=1)

    def start_next_chunk(self, destination):
        """
        signals to the receiver to increment to the next chunk

        chunk size is determined by the size of ICMP's ID field (two bytes)
        2^16 - 1 == 65535

        we don't send any messages to syncronize the chunk number instead this
        is fully handled by the receiver. Since we send 15 packets at a time
        and wait for responses to each packet + this being a pretty slow protocol
        this should be ok.
        """

        print("max icmp id reached, starting next chunk")
        sr(IP(dst=destination) / self.next_chunk_icmp)

    def transmit_file(self):
        self.pkts = []
        id_counter = 1

        with open(self.filename, "rb") as f:
            while file_bytes := f.read(2):
                try:
                    identifier = int(id_counter).to_bytes(2, "big")
                except OverflowError:
                    # since 2^16 - 1 is a multiple of 15 this should only occur after our buffer has been emptied
                    if len(self.pkts) == 0:
                        self.start_next_chunk(self.destination)
                        id_counter = 1
                        identifier = int(id_counter).to_bytes(2, "big")
                    else:
                        raise

                self.pkts.append(
                    IP(dst=self.destination)
                    / ICMP(
                        id=int.from_bytes(identifier, "big"),
                        seq=int.from_bytes(file_bytes, "big"),
                    )
                )

                if len(self.pkts) == 15:
                    sr(self.pkts, retry=3, timeout=1)
                    print(f"sent 15 packets last id is {id_counter}")
                    self.pkts = []

                id_counter += 1

        # send any packets remaining in our buffer
        if len(self.pkts) > 0:
            sr(self.pkts, retry=3, timeout=1)
            print(f"sent {len(self.pkts)} last id is {id_counter}")

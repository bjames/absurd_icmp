import lib.icmp_common as icmp_common
import os
import time
from uuid import uuid4
from scapy.all import *

connection_table = {}


class icmpRecv(icmp_common.absurdIcmp):
    def __init__(self, sender_ip: str, control_code: int):

        self.received_data = [[-1] * (self.max_id)]
        self.filename_data = [[-1] * (self.max_id)]
        self.verification_data = [-1] * 16
        self.filename = ""
        self.chunk = 0
        self.last_control_code = self.control_codes["START_TRANSMISSION"]

        if control_code == 0:
            self.sender_ip = sender_ip
            self.transfer_id = uuid4().hex
            self.start_time = time.time()
            self.path = f"{self.sender_ip}/{self.transfer_id}/"
        else:
            raise ValueError(
                f"ICMP seq {control_code} is not valid for new connections"
            )

    def receive_data(self, identifier, seq):

        if self.last_control_code == self.control_codes["STOP_FILENAME"]:
            self.received_data[self.chunk][identifier - 1] = seq
        elif self.last_control_code == self.control_codes["START_FILENAME"]:
            self.filename_data[self.chunk][identifier - 1] = seq
        elif self.last_control_code == self.control_codes["START_VERIFY"]:
            self.verification_data[identifier - 1] = seq

    def prep_next_chunk(self):
        if self.last_control_code == self.control_codes["START_FILENAME"]:
            self.filename_data.append([-1] * (self.max_id))
        elif self.last_control_code == self.control_codes["STOP_FILENAME"]:
            self.received_data.append([-1] * (self.max_id))
        # TODO output the current chunk here and append PARTIAL to the filename
        self.chunk += 1

    def handle_control_codes(self, seq):
        """
        with the exception of START_TRANSMISSION all control codes are handled here
        """

        if seq == self.control_codes["STOP_TRANSMISSION"]:
            self.last_control_code = self.control_codes["STOP_TRANSMISSION"]
            print("File transfer complete, reassembling")
            self.reassemble_and_output_data()
            self.verify_file()
        elif seq == self.control_codes["START_FILENAME"]:
            print("Receiving filename")
            self.last_control_code = self.control_codes["START_FILENAME"]
        elif seq == self.control_codes["STOP_FILENAME"]:
            self.reassemble_filename()
            print("Receiving file contents")
            self.last_control_code = self.control_codes["STOP_FILENAME"]
            self.chunk = 0  # reset chunk to 0
        elif seq == self.control_codes["NEXT_CHUNK"]:
            self.prep_next_chunk()
        elif seq == self.control_codes["START_VERIFY"]:
            self.last_control_code = self.control_codes["START_VERIFY"]
        elif seq == self.control_codes["STOP_VERIFY"]:
            self.last_control_code = self.control_codes["STOP_VERIFY"]
        else:
            raise ValueError(f"Invalid Control Code Received {seq}")

    def verify_file(self):
        digest = self.hash_file(f"{self.path}{self.filename}")
        sender_digest = bytes()

        for byte in self.verification_data:
            sender_digest += byte.to_bytes(2, "big")

        print(digest)
        print(sender_digest)

        print(digest == sender_digest)

    def reassemble_filename(self):
        for i in range(len(self.filename_data)):
            for j in range(len(self.filename_data[i])):
                try:
                    self.filename += (
                        self.filename_data[i][j].to_bytes(2, "big").decode("ascii")
                    )
                except OverflowError:
                    continue

        print(self.filename)

    def reassemble_and_output_data(self):

        if not os.path.exists(self.path):
            os.makedirs(self.path)

        with open(f"{self.path}{self.filename}", "wb") as f:
            for i in range(len(self.received_data)):
                for j in range(len(self.received_data[i])):
                    try:
                        f.write(self.received_data[i][j].to_bytes(2, "big"))
                    except OverflowError:
                        continue
                    except Exception:
                        pass

        print(f"File received and output to {self.path}{self.filename}")


def process_incoming_packets(pkt):

    sender_ip = pkt[IP].src
    sequence = pkt[ICMP].seq
    identifier = pkt[ICMP].id

    # handle existing connections
    if sender_ip in connection_table:
        if identifier != icmp_common.control_identifier:
            connection_table[sender_ip].receive_data(identifier, sequence)
        else:
            connection_table[sender_ip].handle_control_codes(sequence)

    # handle new connections
    elif identifier == icmp_common.control_identifier:
        connection_table[sender_ip] = icmpRecv(sender_ip, sequence)
        print(f"new transmission from {sender_ip}")
    else:
        print("unhandled ICMP packet received, ignoring")


def start():

    sniff(filter="icmp[icmptype] != icmp-echo", prn=process_incoming_packets)

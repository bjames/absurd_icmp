from scapy.all import ICMP, IP, sr
import hashlib

control_identifier = 0  # when the ID field is 0x00 the sequence contains a control code. Otherwise it contains bytes from a file.


class icmpExfil:

    control_identifier = control_identifier
    low_identifier = 1
    max_id = 65535  # max sequence number (2^16 - 1)

    control_codes = {
        "START_TRANSMISSION": 0,
        "STOP_TRANSMISSION": 1,
        "START_FILENAME": 2,
        "STOP_FILENAME": 3,
        "NEXT_CHUNK": 4,
        "START_VERIFY": 5,
        "STOP_VERIFY": 6,
    }

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

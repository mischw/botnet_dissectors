from dataclasses import dataclass

from base import BaseMessage
from exceptions import DissectError


@dataclass(frozen=True)
class SalityMessage(BaseMessage):

    data:	bytearray
    plain:	bool

    def __str__(self) -> str:
        fstr = "Checksum: %s, Length: %s, Version: %s, URLPackID: %s, Command: %s, Payload: %s"
        return fstr % (hex(self.get_checksum()), hex(self.get_length()), hex(self.get_version()), hex(self.get_urlpackid()), hex(self.get_command()), '0x' + self.get_payload().hex())

    def __repr__(self) -> str:
        return str(self.get_message_fields())

    def get_command_string(self) -> str:
        return {
            1: "Server Test",
            2: "Peer Exchange",
            3: "Hello"
        }[self.get_command()]

    def get_length_raw(self) -> int:
        return len(self.data)

    @staticmethod
    def parse(data_in: bytearray) -> 'SalityMessage':
        """
        Sality v3 Message Structure:

        [offset]	[length]	[field]			[encrypted]		[note]
        -----------|-----------|---------------|---------------|------------
        0			2 byte		checksum		plain			header
        2			2 byte		length			plain			header
        4			1 byte		version			encrypted		header (checksum, length and encryption start from here)
        5			4 byte		urlpackid		encrypted		header
        9			1 byte		command			encrypted		header
        10			? byte		data			encrypted		payload
                                3-32 byte	zero padding	encrypted		payload

        Message structure per command:
        Server Test Request: ServerID + ServerPort (4 + 2 byte)
        Server Test Reply: NewServerID (4 byte)
        Peer Exchange Request: ServerID (4 byte)
        Peer Exchange Reply: Peer_IP + Peer_Port + Peer_ID (4 + 2 + 4 byte) OR empty (0 byte) 
        Hello Request: ServerID (4 byte) OR "OK" + \xFE\xFE\xFE\xFE + URL_Pack (2 + 4 + 142 + x byte)
        Hello Reply: "OK" + \x00 (3 byte) OR "OK" + \xFE\xFE\xFE\xFE + URL_Pack (2 + 4 + 142 + x byte)

        On successful parsing the message is guaranteed to contain a healthy header with at least 10 bytes
        """

        if len(data_in) < 10:
            raise DissectError(
                "Message too small to contain at least a healthy header")

        payload_decrypted = SalityMessage.rc4(
            data_in[4:], data_in[0:2] + data_in[2:4])

        if data_in[0:2] != SalityMessage.crc16(payload_decrypted):
            raise DissectError("Checksum error")

        return SalityMessage(data_in[0:4] + payload_decrypted, True)

    """ ------------------------------------------------------------------ """
    """ additional implementations """
    """ ------------------------------------------------------------------ """

    def get_checksum(self) -> int:
        return int.from_bytes(self.data[0:2], "little")

    def get_length(self) -> int:
        """
        Length of the package content starting from the version field until the end, including padding
        Example: Empty package consists of checksum (2), length (2), version (1), urlpackid (4) and command (1) = 10 bytes.
        This method would return 6 bytes accounting for version, urlpackid and command.
        """
        return int.from_bytes(self.data[2:4], "little")

    def get_version(self) -> int:
        return int.from_bytes(self.data[4:5], "little")

    def get_urlpackid(self) -> int:
        return int.from_bytes(self.data[5:9], "little")

    def get_command(self) -> int:
        return int.from_bytes(self.data[9:10], "little")

    def get_payload(self) -> bytearray:
        return self.data[10:]

    def get_urlpack_fields(self, b: bytearray) -> dict:
        url_list_size = int.from_bytes(b[136:140], "little")
        return {
            'signature': b[:128].hex(),
            'version': int.from_bytes(b[128:132], "little"),
            # 0 = direct List, 1 = indirect list
            'listtype': int.from_bytes(b[132:133], "little"),
            # 0 = all, 1 = servers, 2 = clients
            'recipients': int.from_bytes(b[133:134], "little"),
            'frequency':  int.from_bytes(b[134:136], "little"),  # minutes
            'url_list_size': url_list_size,  # max 1024 bytes
            # max 30
            'url_list_entries': int.from_bytes(b[140:141], "little"),
            'installed': int.from_bytes(b[141:142], "little"),  # ?
            # \x00 terminated strings, last string has \x00\x00\x00
            'urls': b[142:142 + url_list_size].rstrip(b'\x00').split(b'\x00')
        }

    def get_server_id_class(self, server_id: int) -> str:
        if server_id == 1:
            return "undecided"
        elif server_id < 16000000:
            return "non-superpeer"
        elif 16000000 <= server_id <= 20000000:
            return "superpeer"
        else:
            return "invalid"

    def get_header_fields(self) -> dict:
        return {
            'checksum': self.get_checksum(),
            'length': self.get_length(),
            'version': self.get_version(),
            'urlpackid': self.get_urlpackid(),
            'command': self.get_command()
        }

    def get_message_fields(self) -> dict:
        return {
            'header': self.get_header_fields(),
            'payload': self.get_payload_fields()
        }

    def get_payload_fields(self) -> dict:
        """
        Return a dict with all the fields contained in the payload
        Payload meaning in all bytes after the first 10 bytes of header
        """
        # get payload without the trailing zeros
        cmd = self.get_command()
        p = self.get_payload()
        p_rsz = p.rstrip(b'\x00')  # payload with rightstripped zero bytes
        if len(p_rsz) == 0:
            return {}

        # check command
        if cmd == 1:  # Server Test
            if 5 <= len(p_rsz) <= 6:  # REQUEST
                return {'server_id': int.from_bytes(p[0:4], "little"), 'server_port': int.from_bytes(p[4:6], "little")}
            elif len(p_rsz) < 5:  # REPLY:
                return {'new_server_id': int.from_bytes(p[0:4], "little")}
            else:
                return {'error': f"error parsing server test message: {p.hex()}"}
        elif cmd == 2:  # Peer Exchange
            if len(p_rsz) == 0:  # REPLY (empty)
                return {}
            elif 1 <= len(p_rsz) <= 4:  # REQUEST
                return {'server_id': int.from_bytes(p[0:4], "little")}
            elif 7 <= len(p_rsz) <= 10:  # REPLY (non-empty)
                # TODO why is this not in little endian like the other fields?
                ip = f"{p[0]}.{p[1]}.{p[2]}.{p[3]}"
                port = int.from_bytes(p[4:6], "little")
                return {'peer_ip': ip, 'peer_port': port, 'peer_server_id': int.from_bytes(p[6:10], "little")}
            else:
                return {'error': f"error parsing peer exchange message: {p.hex()}"}
        elif cmd == 3:  # Hello
            if len(p_rsz) == 2:  # REPLY (without URL pack)
                return {'ack': p[0:2].decode()}
            elif 1 <= len(p_rsz) <= 4:  # REQUEST (without URL pack)
                return {'server_id': int.from_bytes(p[0:4], "little")}
            # REQUEST OR REPLY (!) = "OK" + \xFE\xFE\xFE\xFE + at least 128+4+1+1+2+4+1+1 (142) byte for an empty URL pack
            elif len(p_rsz) > (6 + 142):
                return {'ack': p[0:2].decode(), 'delimiter': p[2:6], 'urlpack': self.get_urlpack_fields(p[6:])}
            else:
                return {'error': f"error parsing hello message: {p.hex()}"}
        else:
            raise DissectError(f"Uknown command: {cmd}")

    @staticmethod
    def rc4(data: bytearray, key: bytearray) -> bytearray:
        """
        RC4 encryption algorithm
        """
        S = list(range(256))
        j = 0
        out = bytearray()

        # KSA
        for i in range(256):
            j = (j + S[i] + (key[i % len(key)])) % 256
            S[i], S[j] = S[j], S[i]

        # PRGA
        i = j = 0
        for char in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            out.append(char ^ S[(S[i] + S[j]) % 256])
        return out

    @staticmethod
    def crc16(data: bytearray) -> bytearray:
        """
        CRC-16/MODBUS checksum
        Polynomial: 0x8005
        Init: 0xFFFF
        """
        crc = 0xFFFF
        for c in data:
            crc = (crc ^ c)
            counter = 0
            while counter < 8:
                if (crc & 1) == 0:
                    crc = (crc >> 1)
                else:
                    crc = ((0 | (crc >> 1)) ^ 0xA001)
                counter += 1
        byte1 = crc & 0xFF
        byte2 = (crc >> 8) & 0xFF
        return bytearray([byte1, byte2])

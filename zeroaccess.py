import binascii
from dataclasses import dataclass

from base import BaseMessage
from exceptions import DissectError


@dataclass(frozen=True)
class ZeroAccessMessage(BaseMessage):

	data:	bytearray
	plain:	bool

	def __str__(self) -> str:
		fstr = "Checksum: %s, Command: %s, Flag: %s, Payload: %s"
		return fstr % (hex(self.get_checksum()), self.get_command_string(), hex(self.get_flag()), '0x' + self.get_payload().hex())

	def __repr__(self) -> str:
		return ' '.join(["0x{:02x}".format(b) for b in self.data])

	def get_command_string(self) -> str:
		return {
			'4c746567': "getL",
			'4c746572': "retL"
		}[self.get_command().hex()]

	def get_length_raw(self) -> int:
		return len(self.data)

	@staticmethod
	def parse(data_in: bytearray) -> 'ZeroAccessMessage':
		"""
		ZeroAccess Message Structure:

		[offset]	[length]	[field]			[encrypted]		[note]
		-----------|-----------|---------------|---------------|------------
		0			4 byte		checksum		encrypted		header (checksum starts here, for calculating, the checksum field is set to 0)
		4			4 byte		command			encrypted		header
		8			4 byte		flag			encrypted		header
		12			? byte		data			encrypted		payload		
		"""

		if len(data_in) < 16:
			raise DissectError(
				"Message too small to contain at least a healthy header")

		payload_decrypted = ZeroAccessMessage.decrypt_xor(data_in, "ftp2")

		# check crc32
		crc32 = binascii.crc32(
			b"\x00\x00\x00\x00" + payload_decrypted[4:]).to_bytes(4, byteorder='little')
		if bytearray(payload_decrypted[0:4]) != bytearray(crc32):
			raise DissectError("Checksum error")

		return ZeroAccessMessage(payload_decrypted, True)

	""" ------------------------------------------------------------------ """
	""" additional implementations """
	""" ------------------------------------------------------------------ """

	def get_checksum(self) -> int:
		return int.from_bytes(self.data[0:4], "little")

	def get_command(self) -> bytearray:
		return self.data[4:8]

	def get_flag(self) -> int:
		return int.from_bytes(self.data[8:12], "little")

	def get_payload(self) -> bytearray:
		return self.data[12:]

	def get_peer_list(self) -> list[str]:
		# TODO there is a lot more to parse here. For our use case this here is enough
		if self.get_command_string() != "retL":
			raise DissectError("Not a retL message")
		peers = []
		# 16 peers, each having 4 byte ip, 4 byte timestamp
		payload = self.get_payload()
		n_peers = int.from_bytes(payload[0:4], byteorder='little')
		entry_len = 8
		offset = 4
		for i in range(0 + offset, entry_len * n_peers + offset, entry_len):
			ip_bytes = payload[i:i + 4]
			ip_str = '.'.join("%d" % b for b in ip_bytes)
			peers.append(ip_str)
		return peers

	@staticmethod
	def decrypt_xor(payload_bytes: bytearray, key: str) -> bytearray:
		order = 'little'
		# prepare key
		# b'ftp2' / 0x66 0x74 0x70 0x32 / The default encryption key for zero access
		key_bytes = key.encode()
		key_int = int.from_bytes(key_bytes, "big")  # 1718906930

		dec = bytearray()

		# iterate payload
		for i in range(0, len(payload_bytes), 4):
			payload_dword = payload_bytes[i:i+4]
			payload_int = int.from_bytes(payload_dword, byteorder=order)

			xor = payload_int ^ key_int
			dec.extend(xor.to_bytes(4, byteorder=order))
			#print("Cipher XOR Key = %s XOR %s = %s" % (hex(payload_int), hex(key_int), hex(xor)))

			# rotate key					# example for first iteration:
			key_bin_str = bin(key_int)		# '0b1100110011101000111000000110010'
			prefix = key_bin_str[0:2]		# '0b'
			data = key_bin_str[2:]			# '1100110011101000111000000110010'
			# '01100110011101000111000000110010' (zero fill in front to 32 bits)
			data = data.rjust(32, '0')
			# '11001100111010001110000001100100' (left shift rotated)
			rol = data[1:] + data[0]
			key_int = int(prefix + rol, 2)  # 3437813860
			
		return dec

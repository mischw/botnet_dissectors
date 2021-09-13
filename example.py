import unittest

from sality import DissectError, SalityMessage
from zeroaccess import DissectError, ZeroAccessMessage


class TestStringMethods(unittest.TestCase):
	"""
	SOme simple test cases for the dissectors of Sality and ZeroAccess
	"""

	def test_zeroaccess_basic_functions_getL(self):
		data = b"\xcc\x3a\x06\x08\x28\x94\x8d\xab\xc9\xc0\xd1\x99\xa5\x48\xbf\x8c"
		msg = ZeroAccessMessage.parse(data)

		# check header
		self.assertEqual(msg.get_checksum(), 1852984062)
		self.assertEqual(msg.get_command_string(), "getL")
		self.assertEqual(msg.get_flag(), 0)

		# check length
		self.assertEqual(msg.get_length_raw(), 16)

		# not a retL message
		with self.assertRaises(DissectError):
			msg.get_peer_list()
		
		# nodeID
		self.assertEqual(msg.get_payload(), bytearray(b'6\xc9\x1c\xbf'))

	def test_zeroaccess_retL(self):
		data = b"\x85\x61\xd7\x71\x28\x94\x8d\xbe\xc9\xc0\xd1\x99\x83\x81\xa3\x33\x6a\x6d\xcf\xe2\x23\x55\x8f\xce\xd5\xbb\xe7\xe3\x43\x4a\x39\x3a\xdd\xce\x06\xb9\xbd\x37\xe1\xe8\xfb\x61\x69\x87\x41\xc0\x80\xa3\x34\xf5\x2c\x63\xbd\x1f\x07\x8e\xe8\x4d\x3c\xde\x4e\x60\x18\x38\xc2\x98\xcf\x8e\x9d\x9f\x65\xe0\x65\x67\x34\x3e\xd5\x60\x92\x81\xe1\x99\xdb\xfd\xf9\x9d\x4d\x06\x9b\x63\x64\xf2\x40\x69\x32\x19\xf6\x8a\x9b\xcc\x99\xbb\xcd\x64\xb7\x2f\x64\x37\xfb\xf0\x32\x93\x76\xb9\x9a\xd8\x7d\xdd\xcf\x4c\x7f\xe2\x60\x67\x65\x6b\x3b\x33\x43\x8e\x89\x98\x19\xb3\xe9\xcc\x95\x3e\x2c\x67\xed\xd2\xa2\x33\x26\x03\x47\x67"
		msg = ZeroAccessMessage.parse(data)
		self.assertEqual(msg.get_command_string(), "retL")
		self.assertEqual(msg.get_length_raw(), 148)
		ref = ['76.110.136.133', '76.183.251.126', '187.252.118.205', '98.168.169.86', '83.211.47.36', '117.212.48.194', '182.254.253.254', '180.254.253.254',
			   '166.254.253.254', '135.254.253.254', '134.254.253.254', '119.254.253.254', '117.254.253.254', '115.254.253.254', '113.254.253.254', '92.254.253.254']
		self.assertEqual(msg.get_peer_list(), ref)

	def test_sality_rc4(self):
		data = bytearray(b'\xAA\xBB\xCC\xDD')
		key = b'\x11\x11'
		cipher = SalityMessage.rc4(data, key)
		self.assertEqual(cipher, b'\x26\x30\xc3\xca')

	def test_sality_crc16(self):
		data = bytearray(b'\xAA\xBB\xCC\xDD')
		checksum = SalityMessage.crc16(data)
		self.assertEqual(checksum, b'\xc4\x80')

	def test_sality_message_parser(self):
		# all ok
		data = bytearray.fromhex('390c17005d4d18a0c6950925e043f28e84d2145f7704e06e6f9a24')
		msg = SalityMessage.parse(data)
		#print(msg)

		# changed one char -> exception because of wrong checksum
		data_error = bytearray.fromhex('390c17005d4d18a0c6950925e043f28e84d3145f7704e06e6f9a24')
		with self.assertRaises(DissectError):
			msg = SalityMessage.parse(data_error)

		# one more test. this one is from a live client
		data_live = bytearray.fromhex('458b1f0042f0581cf4123909367ba172c0288a93b44ed9e59c1c17b20ae67d0abc861e')
		msg = SalityMessage.parse(data_live)

		# test the getters
		self.assertEqual(msg.get_checksum(), 35653)
		self.assertEqual(msg.get_length(), 31)
		self.assertEqual(msg.get_version(), 3)
		self.assertEqual(msg.get_urlpackid(), 215)
		self.assertEqual(msg.get_command(), 3)

	def test_sality_message_parser_long(self):
		# This is a special message. It is a very long hello message. It contains updated URLs for a botnet client which has just started
		data = bytearray.fromhex('5ef2020229ef8d010a3ea621d7b100516ff69b6ca61a4ca996bb8e87e32fc3b7c526f6005ddd9ebb55f7277ddad1c0d74416d06819f90075f93bd35199a7062ea26634be4fa46e5df814e65ca1d24f8cc9705643926f7c07cdebadf51b10ad6ff9e97fe104f93c45e6c28978a45a520f5cf6209b4661a9c59ec2b639efc2b7318932b0c978cc5a085e0076f7cbeff44290fc7f238cbe27b094a6615a4773f9f534094824cc181c757756012eeac04448a4d2a18879caba161cf7ef358274440ef623f6ab82b9e51af8ee3660a04420c94021eb4f8324c2cc086e78218fb0156daff325eead415533522f77d30942ce8562fa907dbf3b6113b562480df80d821488ee8dfacb383955554bd434797cf55efb53a669aedbc82d1b58411568d50cf36188a9412115143d3f305389c8246cd645dbe51a57685e293d66c0b3208339ff27d51e6dd1accfa114ab0cc0d187fa22c0fc3e198388e4ba3ffdcdc7621d74d7b9b3ba44ddba27b985e54362881fcadae39aee7ab2e2cd01e8c6405698a2b47201dab49f2a9d7e98efe83ff6d0f8037b8e3863c04fdaf5bcf4cf6c6d8e2ff7c0dca86b90995f04e157a9a2820fa26a11db476762e4908c92134c941f9ca925278c12b8b635231ad64141aa202c06d2f7b950713b2ddd820ca1d0b99987a26f48f3ed0796dfaa6ac388949202cb82b72caf15e89ec86f48ad70a1b7c34a4fa1517010eee6c6c7')
		msg = SalityMessage.parse(data)
		self.assertEqual(msg.get_command(), 3)
		#print(msg)

	def test_sality_str_repr_method(self):
		data = bytearray.fromhex('390c17005d4d18a0c6950925e043f28e84d2145f7704e06e6f9a24')
		msg = SalityMessage.parse(data)
		self.assertEqual(repr(msg), "{'header': {'checksum': 3129, 'length': 23, 'version': 3, 'urlpackid': 390, 'command': 2}, 'payload': {'peer_ip': '200.84.139.52', 'peer_port': 8361, 'peer_server_id': 18420792}}")
		self.assertEqual(str(msg), "Checksum: 0xc39, Length: 0x17, Version: 0x3, URLPackID: 0x186, Command: 0x2, Payload: 0xc8548b34a9203814190100000000000000")


if __name__ == '__main__':
	unittest.main()

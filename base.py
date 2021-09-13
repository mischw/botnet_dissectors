from dataclasses import dataclass


@dataclass(frozen=True)
class BaseMessage:
	"""
	Base class with methods all dissectors should implement at minimum
	"""

	def __str__(self) -> str:
		"""
		Data presented as human readable string
		"""
		pass

	def __repr__(self) -> str:
		"""
		Data presented as unambiguous string
		"""
		pass

	def get_command_string(self) -> str:
		"""
		Get the command of the message as string
		"""
		pass

	def get_length_raw(self) -> int:
		"""
		Get the length of the message as a whole in bytes
		"""
		pass

	@staticmethod
	def parse(data: bytearray) -> 'BaseMessage':
		"""
		Return a parsed message of the respective botnet implementation
		"""
		pass

class DissectError(Exception):
	"""
	Error when
			- initially parsing / constructing a message (Checksum error, message to small, ...) or
			- trying to access data / certain attributes (No payload, payload too small, payload does make no sense)
	May also occur when encountering edge cases not yet handled by the dissector
	"""
	pass

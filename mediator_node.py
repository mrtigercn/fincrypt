import os, ConfigParser

from twisted.internet import reactor, protocol, defer
from twisted.protocols import basic

from common import COMMANDS, display_message, validate_file_md5_hash, get_file_md5_hash, read_bytes_from_file, clean_and_split_input

import pickle, base64

class FincryptMediatorProtocol(basic.LineReceiver):
	delimiter = '\n'
	
	def connectionMade(self):
		self.setLineMode()
		print "Client Connected"
		self.transport.write("""Successfully Connected to Mediator\n""")
	
	def lineReceived(self, line):
		print line
		if line[0:9] == 'Node Type':
			if line[12:] == 'Storage':
				self.type = 'Storage'
				self.transport.write("""get details\n""")
			else:
				self.type = 'Client'
		elif line[0:15] == 'Storage Details':
			self.factory.storage_nodes.append(pickle.loads(base64.b64decode(line[15:])))
			print self.factory.storage_nodes

class FincryptMediatorFactory(protocol.ServerFactory):
	protocol = FincryptMediatorProtocol
	
	def __init__(self):
		self.clients = []
		self.storage_nodes = []
		self.deferred = defer.Deferred()

if __name__ == '__main__':
	config = ConfigParser.ConfigParser()
	config.readfp(open('mediator.cfg'))
	configport = int(config.get('mediator', 'port'))
	
	reactor.listenTCP(configport, FincryptMediatorFactory())
	reactor.run()

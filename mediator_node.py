import os, ConfigParser

from twisted.internet import reactor, protocol, defer
from twisted.protocols import basic

from common import COMMANDS, display_message, validate_file_md5_hash, get_file_md5_hash, read_bytes_from_file, clean_and_split_input

import pickle, base64, hashlib

from Crypto.PublicKey import RSA

class FincryptMediatorProtocol(basic.LineReceiver):
	delimiter = '\n'
	
	def connectionMade(self):
		self.setLineMode()
		print "Client Connected"
		self.state = 'REGISTER'
		self.transport.write("""REGISTER\n""")
	
	def lineReceived(self, line):
		if self.state == 'REGISTER':
			self.transport.write("Registering...\n")
			self.handle_REGISTER(line)
	
	def handle_REGISTER(self, line):
		self.publickey, self.detail_string, self.signature = pickle.loads(base64.b64decode(line))
		if self.publickey.verify(self.detail_string, self.signature):
			self.name = hashlib.md5(self.publickey.exportKey()).hexdigest()
			data = pickle.loads(base64.b64decode(self.detail_string))
			print data
			if data[0] == 'STORAGE':
				self.type = 'STORAGE'
				self.ip = data[1]
				self.port = data[2]
				self.freespace = data[3]
				self.factory.storage_nodes[self.name] = self
				print 'Storage Node %s connected at %s:%s' % (self.name, self.ip, self.port)
				self.transport.write("Confirmed Registration\n")
			else:
				self.factory.clients[self.name] = self
				self.type = 'CLIENT'
				self.transport.write("Confirmed Registration\n")
		else:
			self.transport.write("Public Key not verified!\n")
	
	def rawDataReceived(self, data):
		print "Uh oh"

class FincryptMediatorFactory(protocol.ServerFactory):
	protocol = FincryptMediatorProtocol
	
	def __init__(self):
		self.clients = {}
		self.storage_nodes = {}
		self.deferred = defer.Deferred()

def get_rsa_key(config):
	try:
		rsa_key_file = config.get('mediator', 'rsa_file')
		rsa_file = open(rsa_key_file, 'r')
		rsa_key = RSA.importKey(rsa_file.read())
		rsa_file.close()
	except ConfigParser.NoOptionError:
		rsa_key_file = 'mediator.key'
		config.set('mediator', 'rsa_file', rsa_key_file)
		rsa_key = RSA.generate(4096)
		rsa_file = open(rsa_key_file, 'w')
		rsa_file.write(rsa_key.exportKey())
		rsa_file.close()
	return rsa_key

if __name__ == '__main__':
	config = ConfigParser.ConfigParser()
	config.readfp(open('mediator.cfg'))
	configport = int(config.get('mediator', 'port'))
	rsa_key = get_rsa_key(config)
	
	reactor.listenTCP(configport, FincryptMediatorFactory())
	reactor.run()

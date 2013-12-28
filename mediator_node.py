import os, ConfigParser

from twisted.internet import reactor, protocol, defer
from twisted.protocols import basic

from common import COMMANDS, display_message, validate_file_md5_hash, get_file_md5_hash, read_bytes_from_file, clean_and_split_input

import pickle, base64, hashlib, random

from Crypto.PublicKey import RSA

class FincryptMediatorProtocol(basic.LineReceiver):
	delimiter = '\n'
	
	def connectionMade(self):
		self.setLineMode()
		print "Client Connected"
		self.transport.write(self.encode(("REGISTER",)) + "\n")
	
	def connectionLost(self, reason):
		if self.type == 'CLIENT':
			del self.factory.clients[self.name]
			print "Client %s disconnected" % (self.name,)
		elif self.type == 'STORAGE':
			del self.factory.storage_nodes[self.name]
			print "Storage Node %s disconnected" % (self.name,)
		else:
			print "Unregistered Connection Dropped"
	
	def lineReceived(self, line):
		message = self.parse_message(line)
		cmd, msg = message[0], message[1:]
		print 'CMD:', cmd
		if cmd == 'REGISTER':
			self.handle_REGISTER(msg)
		elif cmd == 'FILESENT':
			print msg
		elif self.state == 'CONNECTED' and self.type == 'CLIENT':
			self.handle_CLIENT(msg)
		elif self.state == 'CONNECTED' and self.type == 'STORAGE':
			self.handle_STORAGE(msg)
	
	def handle_REGISTER(self, msg):
		global rsa_key
		key_export = ''.join(rsa_key.publickey().exportKey().splitlines())
		self.transport.write(self.encode(("PRINT", "Registering...")) + "\n")
		self.transport.write(self.encode(("MEDREG", key_export)) + '\n')
		self.publickey, self.detail_string, self.signature = msg
		if self.publickey.verify(self.detail_string, self.signature):
			self.name = hashlib.md5(self.publickey.exportKey()).hexdigest()
			data = pickle.loads(base64.b64decode(self.detail_string))
			if data[0] == 'STORAGE':
				self.type = 'STORAGE'
				self.state = 'CONNECTED'
				self.ip = data[1]
				self.port = data[2]
				self.freespace = data[3]
				self.factory.storage_nodes[self.name] = self
				print 'Storage Node %s connected at %s:%s' % (self.name, self.ip, self.port)
				self.transport.write(self.encode(("PRINT", "Confirmed Registration")) + "\n")
			else:
				self.type = 'CLIENT'
				self.state = 'CONNECTED'
				self.redundancy = data[1]
				self.factory.clients[self.name] = self
				print 'Client Node %s connected' % (self.name)
				self.transport.write(self.encode(('REG_CONFIRM',)) + "\n")
		else:
			self.transport.write(self.encode(("ERROR", "Public Key not verified!\n")))
	
	def parse_message(self, line):
		data = pickle.loads(base64.b64decode(line))
		return data
	
	def encode(self, msg):
		data = base64.b64encode(pickle.dumps(msg))
		return data
	
	def handle_CLIENT(self, msg):
		self.detail_string, self.signature = msg
		if self.publickey.verify(hashlib.sha256(self.detail_string).hexdigest(), self.signature):
			data = pickle.loads(base64.b64decode(self.detail_string))
			for x in data:
				if x[0] not in self.factory.files:
					self.factory.files[x[0]] = {}
					self.factory.files[x[0]]['size'] = x[1]
					self.factory.files[x[0]]['current_nonce'] = ''
					self.factory.files[x[0]]['current_sha256'] = x[2]
					self.factory.files[x[0]]['snodes'] = {}
					self.factory.files[x[0]]['snodes']['list'] = []
					snodes = self.factory.storage_nodes.items()
					random.shuffle(snodes)
					found = 0
					y = 0
					while found < self.redundancy:
						if self.factory.storage_nodes[snodes[y][0]].freespace >= x[1]:
							self.factory.storage_nodes[snodes[y][0]].state = 'REGISTER'
							self.factory.files[x[0]]['snodes'][snodes[y][0]] = {}
							self.factory.files[x[0]]['snodes']['list'].append(snodes[y][0])
							found += 1
						y += 1
				first_snode = self.factory.files[x[0]]['snodes']['list'][0]
				global rsa_key
				self.factory.storage_nodes[first_snode].transport.write(self.encode(("NEWFILE", x[0],x[1],self.publickey, '%s' % rsa_key.publickey().exportKey())) + "\n")
				init_ip = self.factory.storage_nodes[first_snode].ip
				init_port = self.factory.storage_nodes[first_snode].port
				filename = x[0]
				self.transport.write(self.encode(("STORAGE_DETAILS", base64.b64encode(pickle.dumps((init_ip, init_port, filename))))) + '\n')
		else:
			self.transport.write("Error! Public key not verified!\n")
	
	def handle_STORAGE(self, msg):
		return
	
	def rawDataReceived(self, data):
		print "Uh oh"

class FincryptMediatorFactory(protocol.ServerFactory):
	protocol = FincryptMediatorProtocol
	
	def __init__(self):
		self.clients = {}
		self.storage_nodes = {}
		self.files = {}
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
	config.write(open('mediator.cfg', 'wb'))
	
	reactor.listenTCP(configport, FincryptMediatorFactory())
	reactor.run()

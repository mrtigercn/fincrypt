import os, ConfigParser, time, sys

from twisted.internet import reactor, protocol, defer, task
from twisted.protocols import basic

from common import COMMANDS, display_message, validate_file_md5_hash, get_file_md5_hash, read_bytes_from_file, clean_and_split_input

import pickle, base64, hashlib, random

import atexit

from Crypto.PublicKey import RSA

class FincryptMediatorProtocol(basic.LineReceiver):
	delimiter = '\n'
	
	def connectionMade(self):
		self.setLineMode()
		print "Client Connected"
		self.transport.write(self.factory.encode(("REGISTER",)) + "\n")
	
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
		message = self.factory.parse_message(line)
		cmd, msg = message[0], message[1:]
		print 'CMD:', cmd
		if cmd == 'REGISTER':
			self.handle_REGISTER(msg)
		elif cmd == 'FILESENT':
			self.handle_FILESENT(msg)
		elif cmd == 'NEWVERIFYHASH' and self.type == 'CLIENT':
			self.handle_NEWVERIFYHASH(msg)
		elif cmd == 'RESOLVESTORAGENODE':
			self.handle_RESOLVESTORAGENODE(msg)
		elif cmd == 'VERIFY' and self.type == 'STORAGE':
			self.handle_STORAGE_VERIFY(msg)
		elif cmd == 'NEWCLIENTFILE':
			self.handle_NEWCLIENTFILE(msg[0])
		elif self.state == 'CONNECTED' and self.type == 'CLIENT':
			self.handle_CLIENT(msg)
		elif self.state == 'CONNECTED' and self.type == 'STORAGE':
			self.handle_STORAGE(msg)
	
	def handle_RESOLVESTORAGENODE(self, msg):
		filename = msg[0]
		if filename in self.factory.files:
			# Need to filter to active only
			snode = self.factory.files[filename]['snodes']['list'][0]
			self.transport.write(self.factory.encode(("NODEDETAILS", self.factory.storage_nodes[snode].ip, self.factory.storage_nodes[snode].port, filename)) + '\n')
		else:
			self.transport.write(self.factory.encode(("NODEDETAILS", "NOT FOUND")) + '\n')
	
	def handle_STORAGE_VERIFY(self, msg):
		filename, sha256hash = msg
		history = self.factory.files[filename]['snodes'][self.name]['history']
		time_spent = time.time() - self.factory.files[filename]['snodes'][self.name]['last_checked']
		self.factory.files[filename]['snodes'][self.name]['last_checked'] = time.time()
		if self.factory.files[filename]['current_sha256'] == sha256hash:
			# Once a payment marketplace is set up, you'll send money to the Storage Node at this point
			self.factory.files[filename]['snodes'][self.name]['history'] = history[0] + 1, history[1] + 1
			self.factory.files[filename]['snodes'][self.name]['status'] = 'VERIFIED'
		else:
			self.factory.files[filename]['snodes'][self.name]['history'] = history[0], history[1] + 1
			self.factory.files[filename]['snodes'][self.name]['status'] = 'DISABLED'
			self.factory.add_node_to_file(filename)
	
	def handle_NEWVERIFYHASH(self, msg):
		detail_string, signature = msg
		if detail_string == 'NA':
			return
		if self.publickey.verify(hashlib.sha256(detail_string).hexdigest(), signature):
			filename, nonce, sha256hash = self.factory.parse_message(detail_string)
			self.factory.files[filename]['current_nonce'] = nonce
			self.factory.files[filename]['current_sha256'] = sha256hash
			self.factory.request_storage_verify(filename, nonce)
	
	def handle_FILESENT(self, msg):
		filename, sha256_hash = msg
		history = self.factory.files[filename]['snodes'][self.name]['history']
		if self.factory.files[filename]['original_sha256'] == sha256_hash:
			self.factory.files[filename]['snodes'][self.name]['history'] = history[0] + 1, history[1] + 1
			self.factory.files[filename]['snodes'][self.name]['status'] = 'VERIFIED'
			self.factory.add_node_to_file(filename)
			self.factory.propogate_file_to_nodes(filename, self.name)
		else:
			self.factory.files[filename]['snodes'][self.name]['history'] = history[0], history[1] + 1
			self.factory.add_node_to_file(filename)
	
	def handle_REGISTER(self, msg):
		global rsa_key
		key_export = ''.join(rsa_key.publickey().exportKey().splitlines())
		self.transport.write(self.factory.encode(("PRINT", "Registering...")) + "\n")
		self.transport.write(self.factory.encode(("MEDREG", key_export)) + '\n')
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
				self.transport.write(self.factory.encode(("PRINT", "Confirmed Registration")) + "\n")
			else:
				self.type = 'CLIENT'
				self.state = 'CONNECTED'
				self.redundancy = data[1]
				self.factory.clients[self.name] = self
				print 'Client Node %s connected' % (self.name)
				self.transport.write(self.factory.encode(('REG_CONFIRM',)) + "\n")
		else:
			self.transport.write(self.factory.encode(("ERROR", "Public Key not verified!\n")))
	
	def handle_NEWCLIENTFILE(self, msg):
		detail_string, signature = msg
		if not self.publickey.verify(hashlib.sha256(detail_string).hexdigest(), signature):
			self.transport.write("Error! Public key not verified!\n")
			return
		filename, filesize, sha256hash = pickle.loads(base64.b64decode(detail_string))
		if filename in self.factory.files:
			print self.factory.files[filename]['original_sha256'] + '\n', sha256hash
		if filename not in self.factory.files:
			self.factory.files[filename] = {}
			self.factory.files[filename]['snodes'] = {}
			self.factory.files[filename]['snodes']['list'] = []
			self.factory.files[filename]['client'] = self.name
			snodes = self.factory.storage_nodes.items()
			random.shuffle(snodes)
			found = 0
			y = 0
			while found < 1 and y < len(self.factory.storage_nodes):
				if self.factory.storage_nodes[snodes[y][0]].freespace >= filesize:
					self.factory.files[filename]['snodes'][snodes[y][0]] = {}
					self.factory.files[filename]['snodes'][snodes[y][0]]['status'] = 'UNVERIFIED'
					self.factory.files[filename]['snodes'][snodes[y][0]]['last_checked'] = time.time()
					self.factory.files[filename]['snodes'][snodes[y][0]]['history'] = (0,0)
					self.factory.files[filename]['snodes']['list'].append(snodes[y][0])
					found += 1
				y += 1
		elif filename in self.factory.files and self.factory.files[filename]['original_sha256'] == sha256hash:
			self.transport.write(self.factory.encode(("PRINT", "File '%s' Up to Date" % filename)) + '\n')
			return
		self.factory.files[filename]['size'] = filesize
		self.factory.files[filename]['current_nonce'] = ''
		self.factory.files[filename]['original_sha256'] = sha256hash
		self.factory.files[filename]['current_sha256'] = sha256hash
		for snode in self.factory.files[filename]['snodes']:
			if snode == 'list':
				continue
			self.factory.files[filename]['snodes'][snode]['status'] = 'UNVERIFIED'
		first_snode = self.factory.files[filename]['snodes']['list'][0]
		global rsa_key
		self.factory.storage_nodes[first_snode].transport.write(self.factory.encode(("NEWFILE", filename, filesize, self.publickey, '%s' % rsa_key.publickey().exportKey())) + "\n")
		init_ip = self.factory.storage_nodes[first_snode].ip
		init_port = self.factory.storage_nodes[first_snode].port
		self.transport.write(self.factory.encode(("STORAGE_DETAILS", base64.b64encode(pickle.dumps((init_ip, init_port, filename, self.factory.files[filename]['snodes']['list']))))) + '\n')
	
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
		self.defer_verification = task.deferLater(reactor, 3600.0, self.init_verification)
	
	def export_files(self):
		return base64.b64encode(pickle.dumps(self.files))
	
	def init_verification(self):
		self.l = task.LoopingCall(self.handle_file_verification)
		self.l.start(60.0)
	
	def handle_file_verification(self):
		for x in self.files:
			if self.files[x]['client'] in self.clients:
				self.request_client_challenge(x)
	
	def request_client_challenge(self, filename):
		# do work here
		client = self.files[filename]['client']
		if client in self.clients:
			nonce = os.urandom(32)
			self.clients[client].transport.write(self.encode(("NEWVERIFYHASH", filename, nonce)) + '\n')
	
	def request_storage_verify(self, filename, nonce):
		for x in self.files[filename]['snodes']['list']:
			if x in self.storage_nodes:
				self.storage_nodes[x].transport.write(self.encode(("VERIFY", filename, nonce)) + '\n')
			else:
				self.files[filename]['snodes'][x]['status'] = 'DISABLED'
				history = self.files[filename]['snodes'][x]['history']
				self.files[filename]['snodes'][x]['history'] = history[0], history[1] + 1
				self.add_node_to_file(filename)
	
	def propogate_file_to_nodes(self, filename, snode):
		ip, port = self.storage_nodes[snode].ip, self.storage_nodes[snode].port
		for x in self.files[filename]['snodes']['list']:
			if x in self.storage_nodes and self.files[filename]['snodes'][x]['status'] == 'UNVERIFIED':
				print x, 'REQUEST', filename
				if x != snode:
					print True
					self.storage_nodes[x].transport.write(self.encode(("REQUESTFILE", filename, ip, port)) + '\n')
			else:
				self.files[filename]['snodes'][x]['status'] = 'DISABLED'
				history = self.files[filename]['snodes'][x]['history']
				self.files[filename]['snodes'][x]['history'] = history[0], history[1] + 1
				self.add_node_to_file(filename)
	
	def add_node_to_file(self, filename):
		snodes = self.storage_nodes.items()
		count = 0
		current_nodes = dict(self.files[filename]['snodes'])
		del current_nodes['list']
		for x in current_nodes:
			if self.files[filename]['snodes'][x] != 'DISABLED':
				count += 1
		random.shuffle(snodes)
		y = 0
		while y < len(self.storage_nodes) and count < self.clients[self.files[filename]['client']].redundancy:
			if self.storage_nodes[snodes[y][0]].freespace >= self.files[filename]['size'] and snodes[y][0] not in self.files[filename]['snodes']:
				self.files[filename]['snodes'][snodes[y][0]] = {}
				self.files[filename]['snodes'][snodes[y][0]]['status'] = 'UNVERIFIED'
				self.files[filename]['snodes'][snodes[y][0]]['last_checked'] = time.time()
				self.files[filename]['snodes'][snodes[y][0]]['history'] = (0,0)
				self.files[filename]['snodes']['list'].append(snodes[y][0])
				count += 1
			y += 1
		print self.storage_nodes, self.files[filename]['snodes']['list']
	
	def parse_message(self, line):
		data = pickle.loads(base64.b64decode(line))
		return data
	
	def encode(self, msg):
		data = base64.b64encode(pickle.dumps(msg))
		return data

def get_rsa_key(config):
	try:
		rsa_key_file = config.get('mediator', 'rsa_file')
		rsa_file = open(rsa_key_file, 'r')
		rsa_key = RSA.importKey(rsa_file.read())
		rsa_file.close()
	except (ConfigParser.NoOptionError, IOError) as e:
		rsa_key_file = configfile + '.key'
		config.set('mediator', 'rsa_file', rsa_key_file)
		rsa_key = RSA.generate(4096)
		rsa_file = open(rsa_key_file, 'w')
		rsa_file.write(rsa_key.exportKey())
		rsa_file.close()
	return rsa_key

if __name__ == '__main__':
	try:
		configfile = sys.argv[1]
	except IndexError:
		configfile = 'mediator'
	config = ConfigParser.ConfigParser()
	config.readfp(open(configfile + '.cfg'))
	configport = int(config.get('mediator', 'port'))
	rsa_key = get_rsa_key(config)
	config.write(open(configfile + '.cfg', 'wb'))
	fmf = FincryptMediatorFactory()
	
	@atexit.register
	def goodbye():
		config.set('mediator', 'files', fmf.export_files())
		config.write(open(configfile + '.cfg', 'wb'))
	
	reactor.listenTCP(configport, fmf)
	reactor.run()
	

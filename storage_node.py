import os, ConfigParser, sys
import json
from urllib2 import urlopen

from twisted.internet import reactor, protocol
from twisted.protocols import basic

from common import COMMANDS, display_message, validate_file_md5_hash, get_file_md5_hash, read_bytes_from_file, clean_and_split_input, get_file_sha256_hash

import client_node

import pickle, base64

from Crypto.PublicKey import RSA

class FileTransferProtocol(basic.LineReceiver):
	delimiter = '\n'
	
	def connectionMade(self):
		self.factory.clients.append(self)
		self.file_handler = None
		self.file_data = ()
		
		self.transport.write('Welcome\n')
		self.transport.write('Type help for list of all the available commands\n')
		self.transport.write('ENDMSG\n')
		
		display_message('Connection from: %s (%d clients total)' % (self.transport.getPeer().host, len(self.factory.clients)))
		
	def connectionLost(self, reason):
		self.factory.clients.remove(self)
		self.file_handler = None
		self.file_data = ()
		
		display_message('Connection from %s lost (%d clients left)' % (self.transport.getPeer().host, len(self.factory.clients)))

	def lineReceived(self, line):
		#display_message('Received the following line from the client [%s]: %s' % (self.transport.getPeer().host, line))
		
		data = self._cleanAndSplitInput(line)
		if len(data) == 0 or data == '':
			return 
		
		command = data[0].lower()
		if not command in COMMANDS:
			self.transport.write('Invalid command\n')
			self.transport.write('ENDMSG\n')
			return
		if command == 'list':
			self._send_list_of_files()
		elif command == 'get':
			try:
				filename = data[1]
			except IndexError:
				self.transport.write('Missing filename\n')
				self.transport.write('ENDMSG\n')
				return
			
			if not self.factory.files:
				self.factory.files = self._get_file_list()
				
			if not filename in self.factory.files:
				self.transport.write('File with filename %s does not exist\n' % (filename))
				self.transport.write('ENDMSG\n')
				return
			
			display_message('Sending file: %s (%d KB)' % (filename, self.factory.files[filename][1] / 1024))
			
			self.transport.write('HASH %s %s\n' % (filename, get_file_md5_hash(filename))
			self.setRawMode()
			
			for bytes in read_bytes_from_file(os.path.join(self.factory.files_path, filename)):
				self.transport.write(bytes)
			
			self.transport.write('\r\n')	
			self.setLineMode()
		elif command == 'put':
			try:
				filename = data[1]
				file_hash = data[2]
				signed_hash = pickle.loads(base64.b64decode(data[3]))
			except IndexError:
				self.transport.write('Missing filename or file MD5 hash\n')
				self.transport.write('ENDMSG\n')
				return
			
			self.file_data = (filename, file_hash, signed_hash)
			
			# Switch to the raw mode (for receiving binary data)
			print 'Receiving file: %s' % (filename)
			self.setRawMode()
		elif command == 'help':
			self.transport.write('Available commands:\n\n')
			
			for key, value in COMMANDS.iteritems():
				self.transport.write('%s - %s\n' % (value[0], value[1]))
			
			self.transport.write('ENDMSG\n')				
		elif command == 'quit':
			self.transport.loseConnection()
			
	def rawDataReceived(self, data):
		filename = self.file_data[0]
		file_path = os.path.join(self.factory.files_path, filename)
		
		display_message('Receiving file chunk (%d KB)' % (len(data)))
		
		if not self.file_handler:
			self.file_handler = open(file_path, 'wb')
		
		if data.endswith('\r\n'):
			# Last chunk
			data = data[:-2]
			self.file_handler.write(data)
			self.setLineMode()
			
			self.file_handler.close()
			self.file_handler = None
			
			if validate_file_md5_hash(file_path, self.file_data[1]):
				print 'md5 Validate Passed for file: %s' % file_path
				if filename in new_files and new_files[filename][0].verify(self.file_data[1],self.file_data[2]):
					self.transport.write('Successful Transfer\n')
					self.transport.write('ENDMSG\n')
				
					display_message('File %s has been successfully transfered' % (filename))
					
					self.factory.message_siblings(new_files[filename][2], ('FILESENT', filename))
					
					del new_files[filename]
					
				else:
					display_message('Public Key Signature not valid')
					self.transport.write('Invalid Public Key Signature\n')
			else:
				os.unlink(file_path)
				self.transport.write('File was successfully transfered but not saved, due to invalid MD5 hash\n')
				self.transport.write('ENDMSG\n')
			
				display_message('File %s has been successfully transfered, but deleted due to invalid MD5 hash' % (filename))
		else:
			self.file_handler.write(data)
		
	def _send_list_of_files(self):
		files = self._get_file_list()
		self.factory.files = files
		
		self.transport.write('Files (%d): \n\n' % len(files))	
		for key, value in files.iteritems():
			self.transport.write('- %s (%d.2 KB)\n' % (key, (value[1] / 1024.0)))
			
		self.transport.write('ENDMSG\n')
			
	def _get_file_list(self):
		""" Returns a list of the files in the specified directory as a dictionary:
		
		dict['file name'] = (file path, file size, file md5 hash)
		"""
		
		file_list = {}
		for filename in os.listdir(self.factory.files_path):
			file_path = os.path.join(self.factory.files_path, filename)
			
			if os.path.isdir(file_path):
				continue
			
			file_size = os.path.getsize(file_path)
			md5_hash = get_file_md5_hash(file_path)

			file_list[filename] = (file_path, file_size, md5_hash)

		return file_list
			
	def _cleanAndSplitInput(self, input):
		input = input.strip()
		input = input.split(' ')
		
		return input

class FileTransferServerFactory(protocol.ServerFactory):
	
	protocol = FileTransferProtocol
	
	def __init__(self, files_path):
		self.files_path = files_path
		
		self.clients = []
		self.files = None
		
	def message_siblings(self, name, message):
		self.root.message_children(self.name, name, message)

class StorageNodeMediatorClientProtocol(basic.LineReceiver):
	delimiter = '\n'
	
	def connectionMade(self):
		self.setLineMode()
		print "Connected to the Mediator Server"
		self.state = 'REGISTER'
	
	def lineReceived(self, line):
		msg = self.parse_message(line)
		cmd, msg = msg[0], msg[1:]
		print cmd, msg
		if cmd == 'NEWFILE':
			self.handle_NEWFILE(msg)
		elif cmd == 'MEDREG':
			self.handle_MEDREG(msg)
		elif cmd == 'REGISTER':
			register_details = self.mediator_details()
			self.transport.write(register_details + '\n')
		elif cmd == 'VERIFY':
			self.handle_VERIFY(msg)
		elif cmd == 'REQUESTFILE':
			self.handle_REQUESTFILE(msg)
		elif cmd == 'PRINT':
			print 'msg:', msg
	
	def handle_REQUESTFILE(self, msg):
		filename, ip, port = msg
		reactor.connectTCP(ip, port, client_node.FileTransferClientFactory('get', self.factory.configpath, filename))
	
	def handle_VERIFY(self, msg):
		filename, nonce = msg
		sha256hash = get_file_sha256_hash(self.factory.configpath + '/' + filename, nonce=nonce)
		self.transport.write(self.encode(("VERIFY", filename, sha256hash)) + '\n')
	
	def parse_message(self, line):
		data = pickle.loads(base64.b64decode(line))
		return data
	
	def encode(self, msg):
		data = base64.b64encode(pickle.dumps(msg))
		return data
	
	def handle_MEDREG(self, msg):
		self.factory.mediators[msg[0]] = self
	
	def handle_NEWFILE(self, msg):
		filename, size, pubkey, medpub = msg
		print filename, size, pubkey
		global new_files
		new_files[filename] = (pubkey, size, medpub)
		self.transport.write(self.mediator_details() + '\n')
		register_details = self.mediator_details()
		self.transport.write(register_details + '\n')
	
	def mediator_details(self):
		detail_string = self.encode(('STORAGE', self.factory.ip, self.factory.port,freespace(self.factory.configpath)))
		signature = self.factory.rsa_key.sign(detail_string, "")
		public_key = self.factory.rsa_key.publickey()
		return self.encode(('REGISTER', public_key, detail_string, signature))

class StorageNodeMediatorClientFactory(protocol.ClientFactory):
	protocol = StorageNodeMediatorClientProtocol
	
	def __init__(self, configpath, configport, rsa_key):
		self.configpath = configpath
		self.ip = publicip()
		self.port = configport
		self.rsa_key = rsa_key
		self.mediators = {}
	
	def get_message(self, name, message):
		if message[0] == 'FILESENT':
			self.mediators[''.join(name.splitlines())].transport.write(base64.b64encode(pickle.dumps((message[0], message[1], get_file_sha256_hash(self.configpath + '/' + message[1])))) + '\n')

def ensure_dir(f):
	if not os.path.exists(f):
		os.makedirs(f)

def freespace(folder):
	ensure_dir(folder)
	s = os.statvfs(folder)
	actual_space = s.f_bsize * s.f_bavail
	promised_space = 0
	for key in new_files:
		promised_space += new_files[key][1]
	return actual_space - promised_space

def publicip():
	return json.load(urlopen('http://httpbin.org/ip'))['origin']

def get_rsa_key(config):
	try:
		rsa_key_file = config.get('storage', 'rsa_file')
		rsa_file = open(rsa_key_file, 'r')
		rsa_key = RSA.importKey(rsa_file.read())
		rsa_file.close()
	except (ConfigParser.NoOptionError, IOError) as e:
		rsa_key_file = configfile + '.key'
		config.set('storage', 'rsa_file', rsa_key_file)
		rsa_key = RSA.generate(4096)
		rsa_file = open(rsa_key_file, 'w')
		rsa_file.write(rsa_key.exportKey())
		rsa_file.close()
	return rsa_key

new_files = {}

class FactoryContainer(object):
	def __init__(self):
		self.servers = {}
	
	def add_child(self, obj, name):
		self.servers[name] = obj
		self.servers[name].root = self
		self.servers[name].name = name
	
	def message_children(self, sender, recipient, message):
		for server in self.servers:
			if server != sender:
				self.servers[server].get_message(recipient, message)
	
	def message_child(self, name, message):
		if name in self.servers.keys():
			self.servers[server].get_message(name, message)

if __name__ == '__main__':
	try:
		configfile = sys.argv[1]
	except IndexError:
		configfile = 'storage'
	config = ConfigParser.ConfigParser()
	config.readfp(open(configfile + '.cfg'))
	configport = int(config.get('storage', 'port'))
	configpath = config.get('storage', 'path')
	rsa_key = get_rsa_key(config)
	config.write(open(configfile + '.cfg', 'wb'))
	
	display_message('Listening on port %d, serving files from directory: %s' % (configport, configpath))
	
	container = FactoryContainer()
	container.add_child(FileTransferServerFactory(configpath), 'ftpserver')
	container.add_child(StorageNodeMediatorClientFactory(configpath, configport, rsa_key), 'mediator')
	reactor.listenTCP(configport, container.servers['ftpserver'])
	reactor.connectTCP('162.243.36.143', 8001, container.servers['mediator'])
	
	reactor.run()

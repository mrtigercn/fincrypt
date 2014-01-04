import os, ConfigParser, sys

from twisted.internet import reactor, protocol, stdio, defer
from twisted.protocols import basic
from twisted.internet.protocol import ClientFactory

from common import COMMANDS, display_message, validate_file_md5_hash, get_file_md5_hash, read_bytes_from_file, clean_and_split_input, get_file_sha256_hash, validate_file_sha256_hash

from dirtools import Dir, DirState

import hashlib, base64, pickle

from file_encrypt import encrypt_file, decrypt_file

from Crypto.PublicKey import RSA

class FileTransferProtocol(basic.LineReceiver):
	delimiter = '\n'
	
	#def maybeDisconnect(self):
	#	global file_count
	#	file_count -= 1
	#	if 0 == file_count:
	#		self.transport.loseConnection()
	
	def _get_file(self, filename):
		self.transport.write('%s %s\n' % ('get', filename))
		#self.maybeDisconnect()
	
	def _send_file(self, file_path, filename):
		file_path = file_path + '/' + filename
		if not os.path.isfile(file_path):
			print "The file '%s' does not exist" % file_path
			return
		
		file_size = os.path.getsize(file_path) / 1024
		
		print 'Uploading file: %s (%d KB)' % (filename, file_size)
		
		global rsa_key
		md5_hash = get_file_md5_hash(file_path)
		signature = rsa_key.sign(md5_hash, '')
		
		self.transport.write('PUT %s %s %s\n' % (filename, md5_hash, base64.b64encode(pickle.dumps(signature))))
		#self.setRawMode()
		for bytes in read_bytes_from_file(file_path):
			self.transport.write(bytes)
		
		self.transport.write('\r\n')   
		
		# When the transfer is finished, we go back to the line mode 
		self.setLineMode()
	
	def connectionMade(self):
		self.buffer = []
		self.file_handler = None
		self.file_data = ()
		print 'Connected to the server'
		
		if self.factory.cmd == 'get':
			self._get_file(self.factory.filename)
		elif self.factory.cmd == 'send':
			self._send_file(self.factory.files_path, self.factory.filename)
		
	def connectionLost(self, reason):
		self.file_handler = None
		self.file_data = ()
		
		print 'Connection to the server has been lost'
		if reactor.running:
			reactor.stop()
	
	def lineReceived(self, line):
		if line == 'ENDMSG':
			#self.factory.deferred.callback(self.buffer)
			self.buffer = []
		if line.startswith('HASH'):
			# Received a file name and hash, server is sending us a file
			data = clean_and_split_input(line)

			filename = data[1]
			file_hash = data[2]
			
			self.file_data = (filename, file_hash)
			self.setRawMode()
		else:
			self.buffer.append(line)
		
	def rawDataReceived(self, data):
		filename = self.file_data[0]
		file_path = os.path.join(self.factory.files_path, filename)
		
		print 'Receiving file chunk (%d KB)' % (len(data))
		
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
				print 'File %s has been successfully transfered and saved' % (filename)
			else:
				os.unlink(file_path)
				print 'File %s has been successfully transfered, but deleted due to invalid MD5 hash' % (filename)
		else:
			self.file_handler.write(data)

class FileTransferClientFactory(protocol.ClientFactory):
	protocol = FileTransferProtocol
	
	def __init__(self, cmd, files_path, filename):
		self.cmd = cmd
		self.files_path = files_path
		self.filename = filename
		self.deferred = defer.Deferred()

def get_dir_changes(directory):
	d = Dir(directory)
	dir_state_new = DirState(d)
	try:
		d2 = Dir('./')
		jsons = d2.files(directory + "*.json")
		jsons.sort(reverse=True)
		dir_state_old = DirState.from_json(jsons[0])
		dir_state_new.to_json()
		return dir_state_new - dir_state_old
	except:
		dir_state_new.to_json()
		return 'new'

def parse_dir_changes(directory, changes, pwd, key):
	if not os.path.exists(directory + '/tmp~'):
		os.makedirs(directory + '/tmp~')
	for file in changes['created'] + changes['updated']:
		if file[-1] == '~' or file[0:4] == 'tmp~':
			continue
		else:
			encrypt_file(key, directory + '/' + file, directory + '/tmp~/' + hashlib.sha256(pwd + root + file).hexdigest())

def parse_new_dir(directory, pwd, key):
	if not os.path.exists(directory + '/tmp~'):
		os.makedirs(directory + '/tmp~')
	d = Dir(directory)
	for root, dirs, files in d.walk():
		for file in files:
			if file[-1] == '~' or root[-1] == '~':
				continue
			else:
				encrypt_file(key, root + '/' + file, directory + '/tmp~/' + hashlib.sha256(pwd + root + file).hexdigest())

def parse_tmp_dir(directory):
	directory = directory + '/tmp~'
	if not os.path.exists(directory):
		return []
	d = Dir(directory)
	tmp_files = []
	for root, dirs, files in d.walk():
		for file in files:
			tmp_files.append((root, file, os.stat(root + '/' + file).st_size, get_file_sha256_hash(root + '/' + file)))
	return tmp_files

def get_rsa_key(config):
	try:
		rsa_key_file = config.get('client', 'rsa_file')
		rsa_file = open(rsa_key_file, 'r')
		rsa_key = RSA.importKey(rsa_file.read())
		rsa_file.close()
	except (ConfigParser.NoOptionError, IOError) as e:
		rsa_key_file = configfile + '.key'
		config.set('client', 'rsa_file', rsa_key_file)
		rsa_key = RSA.generate(4096)
		rsa_file = open(rsa_key_file, 'w')
		rsa_file.write(rsa_key.exportKey())
		rsa_file.close()
	return rsa_key

class MediatorClientProtocol(basic.LineReceiver):
	delimiter = '\n'
	
	def connectionMade(self):
		self.setLineMode()
		print "Connected to the Mediator Server"
	
	def lineReceived(self, line):
		msg = self.parse_message(line)
		cmd, msg = msg[0], msg[1:]
		if cmd == 'REGISTER':
			register_details = self.mediator_details()
			self.transport.write(register_details + '\n')
		elif cmd == 'REG_CONFIRM':
			self.transport.write(self.file_changes() + '\n')
		elif cmd == 'STORAGE_DETAILS':
			data = pickle.loads(base64.b64decode(msg[0]))
			reactor.connectTCP(data[0], data[1], FileTransferClientFactory('send', self.factory.clientdir + '/tmp~', data[2]))
		elif cmd == 'NEWVERIFYHASH':
			self.new_verify_hash(msg)
		else:
			print msg
	
	def new_verify_hash(self, msg):
		filename, nonce = msg
		sha256hash = get_file_sha256_hash(self.factory.clientdir + '/tmp~/' + filename, nonce=nonce)
		detail_string = base64.b64encode(pickle.dumps((filename, nonce, sha256hash)))
		signature = self.factory.rsa_key.sign(hashlib.sha256(detail_string).hexdigest(), "")
		self.transport.write(self.encode(("NEWVERIFYHASH", detail_string, signature)) + '\n')
	
	def parse_message(self, line):
		data = pickle.loads(base64.b64decode(line))
		return data
	
	def encode(self, msg):
		data = base64.b64encode(pickle.dumps(msg))
		return data
	
	def file_changes(self):
		change_list = []
		for x in self.factory.files:
			change_list.append((x[1], x[2], x[3]))
		change_list = base64.b64encode(pickle.dumps(change_list))
		signature = self.factory.rsa_key.sign(hashlib.sha256(change_list).hexdigest(), "")
		return base64.b64encode(pickle.dumps(('CLIENTFILES', change_list, signature)))
	
	def mediator_details(self):
		detail_string = base64.b64encode(pickle.dumps(('CLIENT', self.factory.redundancy)))
		signature = self.factory.rsa_key.sign(detail_string, "")
		public_key = self.factory.rsa_key.publickey()
		return base64.b64encode(pickle.dumps(('REGISTER', public_key, detail_string, signature)))

class MediatorClientFactory(protocol.ClientFactory):
	protocol = MediatorClientProtocol
	
	def __init__(self, clientdir, rsa_key, files, redundancy):
		self.clientdir = clientdir
		self.rsa_key = rsa_key
		self.files = files
		self.file_count = len(self.files)
		self.enc_pwd = enc_pwd
		self.redundancy = redundancy

if __name__ == '__main__':
	# What follows is a bunch of hardcoded stuff for use while building the system.
	try:
		configfile = sys.argv[1]
	except IndexError:
		configfile = 'client'
	config = ConfigParser.ConfigParser()
	config.readfp(open(configfile + '.cfg'))
	clientdir = config.get('client', 'path')
	rsa_key = get_rsa_key(config)
	enc_pwd = config.get('client', 'password')
	key = hashlib.sha256(enc_pwd).digest()
	gdc = get_dir_changes(clientdir)
	if gdc == 'new':
		parse_new_dir(clientdir, enc_pwd, key)
	else:
		parse_dir_changes(clientdir, gdc, enc_pwd, key)
	tmp_files = parse_tmp_dir(clientdir)
	defer.setDebugging(True)
	config.write(open(configfile + '.cfg', 'wb'))
	reactor.connectTCP('162.243.36.143', 8001, MediatorClientFactory(clientdir, rsa_key, tmp_files, 1))
	reactor.run()

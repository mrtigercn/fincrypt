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
		if not os.path.exists(self.factory.files_path):
			os.makedirs(self.factory.files_path)
		self.transport.write('%s %s\n' % ('get', filename))
	
	def _send_file(self, file_path, filename):
		file_path = file_path + '/' + filename
		if not os.path.isfile(file_path):
			print "The file '%s' does not exist" % file_path
			return
		
		file_size = os.path.getsize(file_path) / 1024
		
		print 'Uploading file: %s (%d KB)' % (filename, file_size)
		
		md5_hash = get_file_md5_hash(file_path)
		signature = self.factory.rsa_key.sign(md5_hash, '')
		
		self.transport.write('PUT %s %s %s\n' % (filename, md5_hash, base64.b64encode(pickle.dumps(signature))))
		#self.setRawMode()
		for bytes in read_bytes_from_file(file_path):
			self.transport.write(bytes)
		
		self.transport.write('\r\n')  
		
		#os.unlink(file_path) 
		
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
		#if reactor.running:
		#	reactor.stop()
	
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
			
			print 'gen hash:', get_file_md5_hash(file_path)
			print 'rcv hash:', self.file_data[1]
			
			if validate_file_md5_hash(file_path, self.file_data[1]):
				print 'File %s has been successfully transfered and saved' % (filename)
				try:
					self.factory.client.process_restore_folder()
				except AttributeError:
					return
			else:
				os.unlink(file_path)
				print 'File %s has been successfully transfered, but deleted due to invalid MD5 hash' % (filename)
		else:
			self.file_handler.write(data)

class FileTransferClientFactory(protocol.ClientFactory):
	protocol = FileTransferProtocol
	
	def __init__(self, cmd, files_path, filename, client=None, rsa_key=None):
		self.cmd = cmd
		self.rsa_key = rsa_key
		self.client = client
		self.files_path = files_path
		self.filename = filename
		self.deferred = defer.Deferred()

def get_dir_changes(directory):
	d = Dir(directory)
	dir_state_new = DirState(d)
	try:
		d2 = Dir('./')
		dir_state_old = DirState.from_json(directory + '.json')
		dir_state_new.to_json()
		return dir_state_new - dir_state_old
	except:
		dir_state_new.to_json(fmt=directory + '.json')
		return 'new'

def parse_dir_changes(directory, changes, pwd, key):
	file_dict = {}
	if not os.path.exists(directory + '/tmp~'):
		os.makedirs(directory + '/tmp~')
	for file in changes['created'] + changes['updated']:
		if file[-1] == '~' or file[0:4] == 'tmp~':
			continue
		else:
			original_file = directory + '/' + file
			new_file = hashlib.sha256(pwd + directory + '/' + file).hexdigest()
			encrypt_file(key, original_file, directory + '/tmp~/' + new_file)
			file_dict[new_file] = original_file
	return file_dict

def parse_new_dir(directory, pwd, key):
	file_dict = {}
	curdir = os.getcwd()
	if not os.path.exists(directory + '/tmp~'):
		os.makedirs(directory + '/tmp~')
	d = Dir(directory)
	for root, dirs, files in d.walk():
		for file in files:
			if file[-1] == '~' or root[-1] == '~':
				continue
			else:
				original_file = root + '/' + file
				new_file = hashlib.sha256(pwd + root[len(curdir) + 1:] + '/' + file).hexdigest()
				encrypt_file(key, original_file, directory + '/tmp~/' + new_file)
				file_dict[new_file] = original_file
	return file_dict

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

def parse_existing_clientdir(pwd, directory):
	file_dict = {}
	curdir = os.getcwd()
	d = Dir(directory)
	for root, dirs, files in d.walk():
		for fileName in files:
			if fileName[-1] == '~' or root[-1] == '~':
				continue
			else:
				relFile = root[len(curdir) + 1:] + '/' + fileName
				file_dict[hashlib.sha256(pwd + relFile).hexdigest()] = relFile
	return file_dict

def load_client_wallet(configfile):
	walletfile = configfile + '.wlt'
	
	walletcfg = ConfigParser.ConfigParser()
	
	try:
		walletcfg.readfp(open(walletfile))
	except IOError:
		return 'new', RSA.generate(4096), ConfigParser.ConfigParser()
	
	try:
		files = pickle.loads(base64.b64decode(walletcfg.get('settings', 'files')))
	except:
		files = 'new'
	
	try:
		rsacontent = pickle.loads(base64.b64decode(walletcfg.get('settings', 'rsakey')))
	except:
		rsacontent = RSA.generate(4096)
	
	try:
		configcontent = pickle.loads(base64.b64decode(walletcfg.get('settings', 'config')))
	except:
		configcontent = ConfigParser.ConfigParser()
	
	return files, rsacontent, configcontent

def save_client_wallet(configfile, config, rsa_key, file_dict):
	walletfile = configfile + '.wlt'
	configfile = configfile + '.cfg'
	
	files = base64.b64encode(pickle.dumps(file_dict))
	
	rsacontent = base64.b64encode(pickle.dumps(rsa_key))
	
	configcontent = base64.b64encode(pickle.dumps(config))

	walletcfg = ConfigParser.ConfigParser()
	walletcfg.add_section('settings')
	walletcfg.set('settings', 'rsakey', rsacontent)
	walletcfg.set('settings', 'config', configcontent)
	walletcfg.set('settings', 'files', files)
	walletcfg.write(open(walletfile, 'wb'))

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
			file_changes = self.file_changes()
			for x in file_changes:
				self.transport.write(base64.b64encode(pickle.dumps(("NEWCLIENTFILE", x))) + '\n')
			for x in self.factory.get_files:
				self.transport.write(base64.b64encode(pickle.dumps(("RESOLVESTORAGENODE", x))) + '\n')
		elif cmd == 'STORAGE_DETAILS':
			data = pickle.loads(base64.b64decode(msg[0]))
			reactor.connectTCP(data[0], data[1], FileTransferClientFactory('send', self.factory.clientdir + '/tmp~', data[2], rsa_key=self.factory.rsa_key))
		elif cmd == 'NEWVERIFYHASH':
			self.new_verify_hash(msg)
		elif cmd == 'NODEDETAILS':
			print msg
			if msg[0] != 'NOT FOUND':
				reactor.connectTCP(msg[0], msg[1], FileTransferClientFactory('get', self.factory.clientdir + '/restore~',  msg[2], client=self.factory.client))
		else:
			print msg
	
	def new_verify_hash(self, msg):
		filename, nonce = msg
		try:
			sha256hash = get_file_sha256_hash(self.factory.clientdir + '/tmp~/' + filename, nonce=nonce)
			detail_string = base64.b64encode(pickle.dumps((filename, nonce, sha256hash)))
			signature = self.factory.rsa_key.sign(hashlib.sha256(detail_string).hexdigest(), "")
		except:
			detail_string = "NA"
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
			detail_string = base64.b64encode(pickle.dumps((x[1], x[2], x[3])))
			signature = self.factory.rsa_key.sign(hashlib.sha256(detail_string).hexdigest(), "")
			change_list.append((detail_string, signature))
		return change_list
	
	def mediator_details(self):
		detail_string = base64.b64encode(pickle.dumps(('CLIENT', self.factory.redundancy)))
		signature = self.factory.rsa_key.sign(detail_string, "")
		public_key = self.factory.rsa_key.publickey()
		return base64.b64encode(pickle.dumps(('REGISTER', public_key, detail_string, signature)))

class MediatorClientFactory(protocol.ClientFactory):
	protocol = MediatorClientProtocol
	
	def __init__(self, clientdir, rsa_key, send_files, redundancy, get_files, enc_pwd, client):
		self.clientdir = clientdir
		self.client = client
		self.rsa_key = rsa_key
		self.files = send_files
		self.file_count = len(self.files)
		self.get_files = get_files
		self.enc_pwd = enc_pwd
		self.redundancy = redundancy

def process_file_list(previous_file_dict, current_file_dict):
	get_list = []
	
	if previous_file_dict == 'new':
		return current_file_dict, []
	
	for x in previous_file_dict:
		if x not in current_file_dict:
			get_list.append(x)
	file_dict = dict(previous_file_dict.items() + current_file_dict.items())
	return file_dict, get_list



class ClientNode():
	def __init__(self, configfile, debug=False):
		self.debug = debug
		self.configfile = configfile
		self.wallet_info = load_client_wallet(self.configfile)
		self.previous_file_dict = self.wallet_info[0]
		self.rsa_key = self.wallet_info[1]
		self.config = self.wallet_info[2]
		try:
			self.clientdir = self.config.get('client', 'path')
		except:
			self.clientdir = sys.argv[2]
		
		if not os.path.exists(self.clientdir):
			os.makedirs(self.clientdir)
			
		try:
			self.enc_pwd = self.config.get('client', 'password')
		except:
			self.enc_pwd = sys.argv[3]
		
		self.key = hashlib.sha256(self.enc_pwd).digest()
		
		if os.path.exists(self.clientdir + '/restore~'):
			self.process_restore_folder()
		
		self.existing_file_dict = parse_existing_clientdir(self.enc_pwd, self.clientdir)
		
		try:
			self.med_ip = self.config.get('client', 'ip')
			self.med_port = int(self.config.get('client', 'port'))
		except:
			self.med_ip = '162.243.36.143'
			self.med_port = 8001
		
		self.gdc = get_dir_changes(self.clientdir)
		if self.gdc == 'new':
			self.new_file_dict = parse_new_dir(self.clientdir, self.enc_pwd, self.key)
		else:
			self.new_file_dict = parse_dir_changes(self.clientdir, self.gdc, self.enc_pwd, self.key)
		self.file_dict = dict(self.existing_file_dict.items() + self.new_file_dict.items())
		self.file_dict, self.get_list = process_file_list(self.previous_file_dict, self.existing_file_dict)
		save_client_wallet(self.configfile, self.config, self.rsa_key, self.file_dict)
		self.tmp_files = parse_tmp_dir(self.clientdir)
		
		self.config.set('client', 'path', self.clientdir)
		self.config.set('client', 'password', self.enc_pwd)
		self.config.set('client', 'ip', self.med_ip)
		self.config.set('client', 'port', self.med_port)
		
		self.config.write(open(configfile + '.cfg', 'wb'))
	
	def connect(self):
		defer.setDebugging(self.debug)
		reactor.connectTCP(self.med_ip, self.med_port, MediatorClientFactory(self.clientdir, self.rsa_key, self.tmp_files, 2, self.get_list, self.enc_pwd, self))
		reactor.run()
	
	def process_restore_folder(self):
		restoredir = self.clientdir + '/restore~'
		d = Dir(restoredir)
	
		for root, dirs, files in d.walk():
			for file in files:
				if file in self.file_dict:
					if not os.path.exists(os.path.dirname(self.file_dict[file])):
						os.makedirs(os.path.dirname(self.file_dict[file]))
					decrypt_file(self.key, root + '/' + file, self.file_dict[file])
					os.unlink(root + '/' + file)

if __name__ == '__main__':
	# What follows is a bunch of hardcoded stuff for use while building the system.
	try:
		configfile = sys.argv[1]
	except IndexError:
		configfile = 'client'
	
	cn = ClientNode(configfile, debug=True)
	cn.connect()

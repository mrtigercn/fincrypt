import os, ConfigParser

from twisted.internet import reactor, protocol, stdio, defer
from twisted.protocols import basic
from twisted.internet.protocol import ClientFactory

from common import COMMANDS, display_message, validate_file_md5_hash, get_file_md5_hash, read_bytes_from_file, clean_and_split_input

from dirtools import Dir, DirState
import hashlib
from file_encrypt import encrypt_file, decrypt_file

class FileTransferProtocol(basic.LineReceiver):
	delimiter = '\n'
	
	def maybeDisconnect(self):
		global file_count
		file_count -= 1
		if 0 == file_count:
			self.transport.loseConnection()
	
	def _get_file(self, filename):
		self.transport.write('%s %s\n' % ('get', filename))
		self.maybeDisconnect()
	
	def _send_file(self, file_path, filename):
		file_path = file_path + '/' + filename
		if not os.path.isfile(file_path):
			print "The file '%s' does not exist" % file_path
			return
		
		file_size = os.path.getsize(file_path) / 1024
		
		print 'Uploading file: %s (%d KB)' % (filename, file_size)
		
		self.transport.write('PUT %s %s\n' % (filename, get_file_md5_hash(file_path)))
		#self.setRawMode()
		for bytes in read_bytes_from_file(file_path):
			self.transport.write(bytes)
		
		self.transport.write('\r\n')   
		
		# When the transfer is finished, we go back to the line mode 
		self.setLineMode()
		self.maybeDisconnect()
	
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
			self.factory.deferred.callback(self.buffer)
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
		if file[-1] == '~':
			continue
		else:
			encrypt_file(key, directory + '/' + file, directory + '/tmp~/' + hashlib.sha256(pwd + file).hexdigest())

def parse_new_dir(directory, pwd, key):
	if not os.path.exists(directory + '/tmp~'):
		os.makedirs(directory + '/tmp~')
	d = Dir(directory)
	for root, dirs, files in d.walk():
		for file in files:
			if file[-1] == '~' or root[-1] == '~':
				continue
			else:
				encrypt_file(key, root + '/' + file, directory + '/tmp~/' + hashlib.sha256(pwd + file).hexdigest())

def parse_tmp_dir(directory):
	directory = directory + '/tmp~'
	if not os.path.exists(directory):
		return []
	d = Dir(directory)
	tmp_files = []
	for root, dirs, files in d.walk():
		for file in files:
			tmp_files.append((root, file))
	return tmp_files

if __name__ == '__main__':
	# What follows is a bunch of hardcoded stuff while building the system.
	clientdir = 'clientdir'
	passsword = 'password123'
	key = hashlib.sha256(password).digest()
	gdc = get_dir_changes(clientdir)
	if gdc == 'new':
		parse_new_dir(clientdir, password, key)
	else:
		parse_dir_changes(clientdir, gdc, password, key)
	tmp_files = parse_tmp_dir(clientdir)
	defer.setDebugging(True)
	files = [
		('162.243.36.143', 5001, 'send', 'clientdir', 'test.txt'),
		('162.243.36.143', 5001, 'send', 'clientdir', 'joke.png')
	]
	file_count = len(files)
	for x in files:
		reactor.connectTCP(x[0], x[1], FileTransferClientFactory(x[2], x[3], x[4]))
	reactor.run()

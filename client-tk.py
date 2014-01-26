from Tkinter import *

from client_node import *

class Application(Frame):
	def __init__(self, master=None, configfile='client', debug=False):
		Frame.__init__(self, master)
		self.pack()
		self.client = ClientNode(configfile, debug=debug)
		self.createWidgets()
	
	def createWidgets(self):
		self.QUIT = Button(self)
		self.QUIT["text"] = "Exit"
		self.QUIT["command"] = self.quit
		self.QUIT.pack({"side": "right"})
		
		self.CONNECT = Button(self)
		self.CONNECT["text"] = "Start Backup"
		self.CONNECT["command"] = self.client.connect
		self.CONNECT.pack({"side": "left"})

root = Tk()
app = Application(master=root, debug=True)
app.mainloop()
root.destroy()

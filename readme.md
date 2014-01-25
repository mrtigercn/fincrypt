Fincrypt
========

This project aims to be a distributed, encrypted filestore that is resiliant against monitoring and deletion.

Anyone can run the software to provide more storage space for the network, and each node that provides storage space that is utilized will be paid for their resources in Bitcoin.

### Try It Out
The first time you run the Client software, you'll need to specify a directory and password. Enter the directory you have placed the files in and run the following line:

    python client_node.py client <relative_folder_path> <password>

After this, you can start the client with:

    python client_node.py

I will be running a Mediator and a few Storage Nodes for the time being, but as I will be restarting these fairly frequently as well as updating the software frequently, don't rely on them for the time being.

A client using this software will point their client at a directory (or directories) they wish to have backed up.

Any time the contents of a monitored directory are modified, the modified files will be AES encrypted and then sent to multiple peers for redundant backup.

For the first iterations, revisions will not be tracked. This may change in the future.

Settings will be stored in a config file. Initial versions will require manually editing this file. Future versions will provide a GUI interface.

Storage nodes will be paid once each time period (60 minutes?), every time period they can prove they have successfully stored the files they were entrusted with. There will likely be a random component to the challenges to lessen the load on Storage Nodes.

There will be three types of nodes:
* Client Node - This is an end user who wishes to back up and/or replicate the contents of their computer
* Storage Node - This is a server that provides storage space to any Client Node (through Mediator Nodes) in exchange for Bitcoin.
* Mediator Node - This is a node that coordinates between the Client Nodes and Storage Nodes. It ensures the lowest price necessary is paid and a sufficient amount of redundancy is reached.

### Encryption
All files will be encrypted client-side, so that no one but the owner of the files can see the contents.

### Pricing
Pricing is tricky. In theory, the Storage Nodes should be able to each set an acceptable price for their services, and the Mediator Nodes will be able to match up Client Nodes as long as sufficient supply remains.

However, it also makes sense to allow various Mediator Nodes to bid for storage space.

It seems like setting up a marketplace for these matters is best, and can be done after the rest of the system is implemented.

### Redundancy
Given the distributed nature of this project, the minimum redundancy a Mediator Node should be willing to accept is 2x.

### Payment
A Mediator Node will hold money in escrow for their Client Nodes and pay the utilized Storage Nodes once each time period (60 minutes?) every time the Storage Node successfully answers a "challenge" from the Mediator Node in the form of verifying the hashed output of Files + Nonce for every file the Storage Node is supposed to be storing for the Mediator Node.

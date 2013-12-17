Fincrypt
========

This project aims to be a distributed, encrypted filestore that is resiliant against monitoring and deletion.

The following text aims to describe the envisioned system.

Anyone can run the software to provide more storage space for the network, and each node that provides storage space that is utilized will be paid for their resources in Bitcoin.

Node discovery will work using similar principles to Bittorent peer discovery.

A client using this software will point their client at a directory (or directories) they wish to have backed up.

Any time the contents of a monitored directory are modified, the modified files will be AES encrypted and then sent to multiple peers for redundant backup.

For the first iterations, revisions will not be tracked. This may change in the future.

Settings will be stored in a .env file. Initial versions will require manually editing this file. Future versions will provide a GUI interface.

Storage nodes will be paid once each time period (60 minutes?), every time period they can prove they have successfully stored the files they were entrusted with.

Verification will be handled using Merkle trees or similar.

There will be three types of nodes:
* Client Node - This is an end user who wishes to back up and/or replicate the contents of their computer
* Storage Node - This is a server that provides storage space to any Client Node in exchange for Bitcoin.
* Mediator Node - This is a node that coordinates between the Client Nodes and Storage Nodes. It ensures the lowest price necessary is paid and a sufficient amount of redundancy is reached.

## Client Node
A Client Node will specify one or more folders they wish to keep backed up along with a minimum redundancy requirement.

They will also safely store a encryption/decryption key.

They will pre-pay a Mediator Node for services. An optional alert can be sent to the Client Node if they are in danger of running out of time.

## Storage Node
A Storage Node specifies one or more folders they are willing to allow Client Nodes to use for backed up data in exchange for Bitcoin.

They can set their own price or let if float between Mediator nodes.

Storage Nodes should keep a persistent connection to the Internet or risk missing out on fees.

## Mediator Node
A Mediator Node matches up Client Nodes & Storage Nodes for a small fee.

When a Client Node requests to back up a file, the Mediator Node has a responsibility to find an available Storage Node and direct the Client Node to send their file(s) there.

A variety of pricing schemes should be available to any given Mediator Node. A Mediator node should also be able to store business logic regarding what Client Nodes to accept and what Storage Nodes to use.

A Mediator Node should also periodically ensure the Storage Nodes can prove they still hold all necessary files. This will be accomplished using a Merckle Tree, likely using a new nonce as part of the hash input each time they require proof.

While a Client Node can run their own Mediator Node, it's likely best to trust a third party in order to minimize risk.

### Pricing
Pricing can be tricky. In theory, the Storage Nodes should be able to each set an acceptable price for their services, and the Mediator Nodes will be able to match up Client Nodes as long as sufficient supply remains.

However, it also makes sense to allow various Mediator Nodes to bid for storage space.

It seems like setting up a marketplace for these matters is best, and can be done after the rest of the system is implemented.

### Redundancy
Given the distributed nature of this project, the minimum redundancy a Mediator Node should be willing to accept is 2x.

### Payment
A Mediator Node will hold money in escrow for their Client Nodes and pay the utilized Storage Nodes once each time period (60 minutes?) every time the Storage Node successfully answers a "challenge" from the Mediator Node in the form of verifying the hashed output of Files + Nonce for every file the Storage Node is supposed to be storing for the Mediator Node.

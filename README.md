# Pychain

Toy Blockchain in 200 lines of Python

## Getting Started

Quick steps to get a peer network running locally for fun and profit.

### Prerequisites

Pychain depends on Python 3 with asyncio and websockets, install them if required using

```
pip3 install asyncio
pip3 install websockets
```

### Running a single node

Launch the root node of this peer network

```
./pychain
```

This will launch a single node on HTTP port 6001 for API user and will listen on port 8000 for other joining nodes. Since we started this node as a "root node", it will mine our very first block called the "Genesis Block".

### Starting subsequent nodes

Now that we have our root node up and running, lets start one more node. This time around we don't want this node to mine the Genesis Block, so we will tell it about the other node that is already running. Run this on a different terminal.

```
./pychain -n ws://localhost:8000 -p 6002 -w 8001
```

Nodes in a peer network communicate with each other via the websocket, so we have to mention the root node's websocket address `ws://localhost:8000`. This example is running on the same machine so we specify a different HTTP and Websocket ports for this peer.

### Command line options

```
  -h, --help            show this help message and exit
  -n NODE, --node NODE  Add an root peer. If no peers are specified node will
                        start as root peer
  -p HTTP_PORT, --http-port HTTP_PORT
                        Port on which the HTTP server will run, default port
                        is 6001
  -w WS_PORT, --ws-port WS_PORT
                        Port on which Websocket will run, default Websocket
                        port is 8000
  -d DIFFICULTY, --difficulty DIFFICULTY
                        Number of zeros in the hash, default is 4
```

## LICENSE

This project is released under Apache 2 License - see [LICENSE.txt](LICENSE.txt) for details.

## Acknowledgments

* https://anders.com/blockchain/blockchain.html
* https://github.com/lhartikk/naivechain

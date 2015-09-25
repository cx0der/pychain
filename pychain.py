#!/usr/bin/env python3
#######################
# pychain
#######################

import argparse
import hashlib
import time
import threading
import asyncio
import websockets
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

chain = []
peers = set()
http_port = 6001
ws_port = 8000
difficulty = 4
pattern = ''
maxNonce = 500000

class Block:
	def __init__(self, index, nonce, prev_hash, timestamp, data, hash):
		self.index = index
		self.nonce = nonce
		self.prev_hash = prev_hash
		self.timestamp = timestamp
		self.data = data
		self.hash = hash

def jdefault(o):
	if isinstance(o, list):
		return o
	return o.__dict__

def get_last_block():
	return chain[len(chain) - 1]

def is_block_valid(new_block, last_block):
	if last_block.index + 1 != int(new_block["index"]):
		return False
	if last_block.hash != new_block["prev_hash"]:
		return False
	block_val = str(new_block["index"]) + str(new_block["nonce"]) + new_block["prev_hash"] + \
		str(new_block["timestamp"]) + new_block["data"]
	if calculate_hash(block_val) != new_block["hash"]:
		return False
	return True

def add_block(data):
	prev_block = get_last_block()
	timestamp = time.time()
	new_block = mine_block(prev_block.index + 1, prev_block.hash, timestamp, data)
	chain.append(new_block)
	return new_block

async def notify_node(node, block):
	msg = dict(type="NEW_BLOCK", data=json.dumps(block, default=jdefault))
	async with websockets.connect(node) as websocket:
		await websocket.send(json.dumps(msg))


def send_broadcast(block):
	loop = asyncio.new_event_loop()
	for p in peers:
		loop.run_until_complete(notify_node(p, block))
	loop.close()

class HttpHandler(BaseHTTPRequestHandler):
	def do_GET(self):
		if self.path == '/blocks':
			self.set_response_headers(200)
			# send all the blocks
			self.wfile.write(bytes(json.dumps(chain, default=jdefault), "utf8"))
		elif self.path == '/peers':
			self.set_response_headers(200)
			# send all peers
			self.wfile.write(bytes(json.dumps(peers), "utf8"))
		else:
			# send 401 bad request
			self.set_response_headers(400, "plain/text")
			message = "Bad request"
			self.wfile.write(bytes(message, "utf8"))
		return

	def do_POST(self):
		length = int(self.headers['Content-Length'])
		post_body = json.loads(self.rfile.read(length))
		new_block = add_block(post_body["data"])
		send_broadcast(new_block)
		self.set_response_headers(201)
		self.wfile.write(bytes(json.dumps(new_block, default=jdefault), "utf-8"))

	def set_response_headers(self, code, content_type="application/json"):
		self.send_response(code)
		self.send_header("Content-type", content_type)
		self.end_headers()

def calculate_hash(data_to_hash):
	return hashlib.sha256(data_to_hash.encode("utf-8")).hexdigest()

def mine_block(index, prev_hash, timestamp, data):
	for nonce in range(1, maxNonce):
		blockVal = str(index) + str(nonce) + prev_hash + str(timestamp) + data
		hash = calculate_hash(blockVal)
		if hash[:difficulty] == pattern:
			return Block(index, nonce, prev_hash, timestamp, data, hash)

def get_genisis_block():
	timestamp = time.time()
	return mine_block(0, "0", timestamp, "Genisis Block")

def init_http_server(port, server_class=HTTPServer, handler_class=HttpHandler):
	server_address = ('', port)
	httpd = server_class(server_address, handler_class)
	print('Starting HTTP server on port ', http_port)
	httpd.serve_forever()

async def ws_message_handler(websocket, path):
	peers.add(websocket)
	msg = json.loads(await websocket.recv())

	if msg["type"] == "QUERY_ALL":
		response = json.dumps(chain, default=jdefault)
		await websocket.send(response)
	elif msg["type"] == "NEW_BLOCK":
		print("Verifying received block")
		new_block = json.loads(msg["data"])
		last_block = get_last_block()
		if int(new_block["index"]) > last_block.index:
			if is_block_valid(new_block, get_last_block()):
				print("block verified, adding to chain")
				chain.append(Block(new_block["index"], new_block["nonce"], new_block["prev_hash"],
					new_block["timestamp"], new_block["data"], new_block["hash"]))
			else:
				print("Invalid block. ignore")
		else:
			print("Received blockchain is shorter than the current chain, ignore!")

def init_p2p_server(port):
	p2p = websockets.serve(ws_message_handler, '', port)
	loop = asyncio.new_event_loop()
	asyncio.set_event_loop(loop)
	asyncio.get_event_loop().run_until_complete(p2p)
	print('Starting p2p server on port: ', port)
	asyncio.get_event_loop().run_forever()

async def get_all_blocks(node):
	async with websockets.connect(node) as websocket:
		# Query all the blocks
		msg = dict(type="QUERY_ALL")
		await websocket.send(json.dumps(msg))

		response = await websocket.recv()
		blocks = json.loads(response)
		for b in blocks:
			chain.append(Block(b["index"], b["nonce"], b["prev_hash"], b["timestamp"], b["data"], b["hash"]))

parser = argparse.ArgumentParser()
parser.add_argument("-n", "--node", help="Add an root peer. If no peers are specified node will start as root peer")
parser.add_argument("-p", "--http-port", help="Port on which the HTTP server will run, default port is 6001", type=int)
parser.add_argument("-w", "--ws-port", help="Port on which Websocket will run, default Websocket port is 8000", type=int)
parser.add_argument("-d", "--difficulty", help="Number of zeros in the hash, default is 4", type=int)
args = parser.parse_args()

if args.node:
	peers.add(args.node)
if args.http_port:
	http_port = args.http_port
if args.ws_port:
	ws_port = args.ws_port
if args.difficulty:
	difficulty = args.difficulty

for x in range(difficulty):
	pattern += '0'

http_thread = threading.Thread(target=init_http_server, args=(http_port,))

p2p_thread = threading.Thread(target=init_p2p_server, args=(ws_port,))

if len(peers) == 0:
	print('Initializing as root node...')
	chain.append(get_genisis_block())
	print('Genisis block mined!')
else:
	# Not a root node, connect to an existing node to get all the blocks
	print('Initializing as non-root node...')
	loop = asyncio.new_event_loop()
	loop.run_until_complete(get_all_blocks(next(iter(peers))))
	loop.close()

http_thread.start()
p2p_thread.start()
import collections
import ipaddress
import random
import socket
import struct
import threading
import time
import traceback

from .block import Block, BlockHeader
from .bloom import Bloom
from .inv import Inv
from .serialize import Serialize
from .transaction import Transaction
from .util import *


################################################################################
################################################################################
class OutOfPeers(Exception):
    pass

################################################################################
################################################################################
class Manager(threading.Thread):
    REQUEST_WAIT = 0
    REQUEST_GO = 1
    REQUEST_DONT = 2

    PEER_RECORD_SIZE = 14

    PROTOCOL_VERSION = 60002
    SERVICES = 1
    USER_AGENT = '/Satoshi:0.7.2/'

    BLOCKCHAIN_SYNC_WAIT_TIME = 10

    HEADERS_REQUEST_TIMEOUT   = 25
    GETBLOCKS_REQUEST_TIMEOUT = 60
    BLOCK_REQUEST_TIMEOUT     = 120
    TX_REQUEST_TIMEOUT        = 30

    MAX_MESSAGE_SIZE = 2*1024*1024

    INVENTORY_CHECK_TIME = 3
    MANAGE_INVENTORY_CHECK_TIME = 60
    KEEP_BLOCK_IN_INVENTORY_TIME = 120*60
    KEEP_TRANSACTION_IN_INVENTORY_TIME = 30*60
    REBROADCAST_TRANSACTION_TIME = 30*60

    INVENTORY_FLAG_HOLD_FOREVER = 0x01
    INVENTORY_FLAG_MUST_CONFIRM = 0x02

    def __init__(self, spv=None, peer_goal=1, listen=('', 0)):
        threading.Thread.__init__(self)
        self.spv = spv
        self.peer_goal = peer_goal

        self.peers = {}
        self.peer_addresses_db_file = self.spv.config.get_file("addresses.dat")
        self.peer_address_lock = threading.Lock()
        self.load_peer_addresses()

        self.inv_lock = threading.Lock()
        self.inprogress_invs = {}
        self.inventory = collections.deque()
        self.inventory_items = {}
        self.last_manage_inventory_time = time.time()

        self.blockchain_sync_lock = threading.Lock()

        self.tx_bloom_filter = Bloom(hash_count=32, size=2**23) # Use 8MB for our tx bloom filter

        self.headers_request = None
        self.headers_request_last_peer = None

        if listen is not None:
            if listen[0] == '':
                listen = ('0.0.0.0', listen[1])
            if listen[1] == 0:
                listen = (listen[0], self.spv.coin.DEFAULT_PORT)

        self.listen_address = listen

    def start(self):
        self.running = False
        threading.Thread.start(self)

        # Wait for thread to start ...
        while not self.running:
            pass

    def shutdown(self):
        # Shutdown all peers first
        for _, p in self.peers.items():
            p.shutdown()

        self.running = False

    def join(self, *args, **kwargs):
        kwargs['timeout'] = 3
        for _, p in self.peers.items():
            p.join(*args, **kwargs)
            if p.is_alive():
                import sys
                print("*** STACKTRACE - START :: peer({}) ***".format(p.peer_address))
                code = []
                for thread_id, stack in sys._current_frames().items():
                    code.append("\n# Thread ID: {}".format(thread_id))
                    for filename, lineno, name, line in traceback.extract_stack(stack):
                        code.append('\nFile: "{}", line {}, in {}'.format(filename, lineno, name))
                        if line:
                            code.append("  {}".format(line.strip()))
                
                for line in code:
                    print(line, end='')

                print("\n*** STACKTRACE - END ***")
        threading.Thread.join(self, *args, **kwargs)

    def run(self):
        self.running = True

        if self.spv.logging_level <= DEBUG:
            print("[NETWORK] starting")

        self.start_listening()

        while self.running:
            now = time.time()

            if len(self.peer_addresses) < 5:
                self.get_new_addresses_from_peer_sources()

            self.check_for_incoming_connections()
            self.check_for_dead_peers()
            self.check_for_new_peers()
            self.manage_inventory()

            with self.blockchain_sync_lock:
                if self.headers_request is not None and \
                       ((self.headers_request['peer'].inprogress_command != 'headers' and (now - self.headers_request['time']) >= Manager.HEADERS_REQUEST_TIMEOUT) or \
                        (self.headers_request['peer'].inprogress_command == 'headers' and (now - self.headers_request['peer'].last_data_time) >= Manager.HEADERS_REQUEST_TIMEOUT)):

                    # Misbehaving/dead peer?
                    self.peer_is_bad(self.headers_request['peer'].peer_address)
                    self.headers_request['peer'].state = 'dead'

            time.sleep(0.01)

        if self.spv.logging_level <= DEBUG:
            print("[NETWORK] stopping")

        if self.listen_socket is not None:
            self.listen_socket.close()

    def get_new_addresses_from_peer_sources(self):
        for seed in self.spv.coin.SEEDS:
            for _, _, _, _, ipport in socket.getaddrinfo(seed, None):
                if len(ipport) != 2: # no IPv6 support yet
                    continue
                ip, _ = ipport
                self.add_peer_address((ip, self.spv.coin.DEFAULT_PORT))

    def add_peer_address(self, peer_address):
        if peer_address in self.peer_addresses:
            return True

        try:
            ipaddress.IPv4Address(peer_address[0]).packed
        except ipaddress.AddressValueError:
            # peer_address[0] is probably an IPv6 address
            if self.spv.logging_level <= INFO:
                print("[NETWORK] peer address {} is not valid IPv4".format(peer_address[0]))
            return False

        if self.spv.logging_level <= DEBUG:
            print("[NETWORK] new peer found", peer_address)

        self.peer_addresses[peer_address] = {
            'last_successful_connection_time': 0.0,
            'index': self.peer_index,
        }

        self.update_peer_address(peer_address)

        self.peer_index += 1
        return True

    def update_peer_address(self, peer_address):
        if peer_address not in self.peer_addresses:
            return

        with open(self.peer_addresses_db_file, "ab") as fp:
            data = ipaddress.IPv4Address(peer_address[0]).packed + struct.pack("<Hd", peer_address[1], self.peer_addresses[peer_address]['last_successful_connection_time'])
            fp.seek(self.peer_addresses[peer_address]['index'] * Manager.PEER_RECORD_SIZE, 0)
            fp.write(data)

    def delete_peer_address(self, peer_address):
        if peer_address not in self.peer_addresses:
            return

        old = self.peer_addresses.pop(peer_address)
        self.peer_index -= 1

        with open(self.peer_addresses_db_file, "a+b") as fp:
            assert fp.tell() >= Manager.PEER_RECORD_SIZE  # This has to be true, since self.peer_addresses has at least one entry

            # When files are opened for append, they are positioned at the end of the file. Back up and read the final record, it'll be used to replace 'old'
            fp.seek(fp.tell()-Manager.PEER_RECORD_SIZE, 0) 
            data = fp.read(Manager.PEER_RECORD_SIZE)
            fp.truncate(self.peer_index * Manager.PEER_RECORD_SIZE)

            if old['index'] == (fp.tell() // Manager.PEER_RECORD_SIZE):
                return

            port, _ = struct.unpack("<Hd", data[4:])
            peer_address = (ipaddress.IPv4Address(data[0:4]).exploded, port)
            self.peer_addresses[peer_address]['index'] = old['index']
            fp.seek(old['index'] * Manager.PEER_RECORD_SIZE)
            fp.write(data)
            
    def load_peer_addresses(self):
        self.peer_addresses = {}
        self.peer_index = 0
        try:
            with open(self.peer_addresses_db_file, "rb") as fp:
                while True:
                    data = fp.read(Manager.PEER_RECORD_SIZE)
                    if len(data) == 0:
                        break
                    port, last = struct.unpack("<Hd", data[4:])
                    peer_address = (ipaddress.IPv4Address(data[0:4]).exploded, port)
                    self.peer_addresses[peer_address] = {
                        'last_successful_connection_time': last,
                        'index': self.peer_index,
                    }
                    self.peer_index += 1
            if self.spv.logging_level <= DEBUG:
                print("[NETWORK] {} peer addresses loaded".format(len(self.peer_addresses)))
        except FileNotFoundError:
            pass

    def start_listening(self):
        self.listen_socket = None

        if self.listen_address is None:
            return

        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket.bind(self.listen_address)
        self.listen_socket.setblocking(False)
        self.listen_socket.listen(5)

    def check_for_incoming_connections(self):
        if self.listen_socket is None:
            return

        try:
            sock, peer_address = self.listen_socket.accept()
        except (socket.timeout, BlockingIOError):
            return

        if self.spv.logging_level <= DEBUG:
            print('[MANAGER] incoming connection from {}'.format(peer_address))

        if not self.add_peer_address(peer_address):
            sock.close()
            return

        self.peers[peer_address] = Peer(self, peer_address, sock)
        self.peers[peer_address].start()

    def check_for_dead_peers(self):
        dead_peers = set()

        for peer_address, peer in self.peers.items():
            if peer.is_alive():
                continue
            dead_peers.add(peer_address)

        with self.inv_lock:
            for peer_address in dead_peers:
                peer = self.peers.pop(peer_address)

                if self.headers_request is not None and self.headers_request['peer'] is peer:
                    # We lost a peer who was requesting headers, so let someone else do it.
                    self.headers_request = None
 
                for inv in peer.inprogress_invs:
                    if inv in self.inprogress_invs:
                        self.inprogress_invs.pop(inv)

    def check_for_new_peers(self):
        try:
            while len(self.peers) < self.peer_goal:
                self.start_new_peer()
        except OutOfPeers:
            # TODO - handle out of peers case
            if self.spv.logging_level <= WARNING:
                traceback.print_exc()
        
    def start_new_peer(self):
        peer_addresses = list(self.peer_addresses.keys())
        while len(peer_addresses) > 0:
            k = random.randrange(0, len(peer_addresses))
            peer_addresses[k], peer_addresses[len(peer_addresses)-1] = peer_addresses[len(peer_addresses)-1], peer_addresses[k]
            p = peer_addresses.pop()
            #p_ = ('127.0.0.1', 18333)
            #if p_ not in self.peers:
            #    p = p_
            if p not in self.peers:
                self.peers[p] = Peer(self, p)
                self.peers[p].start()
                break
        else:
            raise OutOfPeers()

    def peer_is_bad(self, peer_address):
        with self.peer_address_lock:
            self.delete_peer_address(peer_address)

    def peer_is_good(self, peer_address):
        p = self.peer_addresses.get(peer_address, None)
        if p is not None:
            p['last_successful_connection_time'] = time.time()
            with self.peer_address_lock:
                self.update_peer_address(peer_address)

    def peer_found(self, peer_address):
        with self.peer_address_lock:
            self.add_peer_address(peer_address)

    def will_request_inv(self, inv):
        # We need to determine if we've ever seen this transaction before. The
        # easy case is if we've previously saved the transaction (for whatever
        # reason) to the txdb.  The harder case is if we've seen it previously
        # but choose to ignore it because it wasn't important.  For the harder
        # case, we can use a bloom filter for broadcasted transactions which
        # means we will sometimes false positive on a transaction we actually
        # do want.  Theoretically that's OK because those 1 in a million times
        # when we get a false positive will be covered when the transaction
        # makes it into a block.  Once we get a block, all transactions in the
        # block are examined.

        with self.inv_lock:
            if inv in self.inprogress_invs:
                return Manager.REQUEST_WAIT

            if inv.type == Inv.MSG_TX:
                if self.spv.txdb.has_tx(inv.hash):
                    return Manager.REQUEST_DONT

                if self.tx_bloom_filter.has(inv.hash):
                    return Manager.REQUEST_DONT

            elif inv.type == Inv.MSG_BLOCK:
                if self.spv.blockchain.get_needs_headers():
                    return Manager.REQUEST_WAIT

                if inv.hash in self.spv.blockchain.blocks:
                    return Manager.REQUEST_DONT

            self.inprogress_invs[inv] = time.time()
            return Manager.REQUEST_GO

    def will_request_headers(self, peer):
        with self.blockchain_sync_lock:
            if not self.spv.blockchain.get_needs_headers():
                return Manager.REQUEST_DONT

            if self.headers_request is not None:
                assert peer is not self.headers_request['peer'], "Don't do that"
                return Manager.REQUEST_WAIT

            if peer is self.headers_request_last_peer:
                return Manager.REQUEST_WAIT

            self.headers_request = {
                'time': time.time(),
                'peer': peer
            }

            self.headers_request_last_peer = peer

            return Manager.REQUEST_GO

    def will_request_blocks(self):
        if self.spv.blockchain.get_needs_headers():
            return Manager.REQUEST_DONT
            
        return Manager.REQUEST_GO

    def received_transaction(self, inv, tx):
        '''tx is None -> peer failed to deliver the transaction'''
        if tx is not None:
            self.add_to_inventory(inv, tx)
            self.tx_bloom_filter.add(inv.hash)
            self.spv.on_tx(tx)

        # Do this after adding the tx to the wallet to handle race condition
        with self.inv_lock:
            if inv in self.inprogress_invs:
                self.inprogress_invs.pop(inv)

    def received_headers(self, headers):
        try:
            return self.spv.blockchain.add_block_headers(headers)
        finally:
            with self.blockchain_sync_lock:
                self.headers_request = None

    def received_block(self, inv, block, syncing_blockchain):
        if not syncing_blockchain:
            self.add_to_inventory(inv, block)
        self.spv.on_block(block)
        self.spv.blockchain.add_block(block)

        with self.inv_lock:
            if inv in self.inprogress_invs:
                self.inprogress_invs.pop(inv)

    def add_to_inventory(self, inv, item, flags=0):
        with self.inv_lock:
            if inv in self.inventory_items:
                return

            self.inventory.append(inv)
            self.inventory_items[inv] = {
                'sent_to'   : set(),
                'inv_to'    : set(),
                'data'      : item.serialize(),
                'time_added': time.time(),
                'time_check': time.time(),
                'last_sent' : 0,
                'flags'     : flags
            }

            # Transactions that have MUST_CONFIRM set have to be added to our txdb, otherwise
            # we'll never be able to confirm their depth
            if (flags & Manager.INVENTORY_FLAG_MUST_CONFIRM) != 0:
                if not self.spv.txdb.has_tx(inv.hash):
                    raise Exception("tx must be present in the transaction database in order to check confirmations")

    def get_inventory_data(self, inv):
        with self.inv_lock:
            if inv not in self.inventory_items:
                return None
            return self.inventory_items[inv]['data']

    def manage_inventory(self):
        # drop blocks and transactions from self.inventory as necessary
        now = time.time()

        if now < self.last_manage_inventory_time + Manager.MANAGE_INVENTORY_CHECK_TIME:
            return

        with self.inv_lock:
            for _ in range(len(self.inventory)):
                inv = self.inventory.popleft()
                item = self.inventory_items.pop(inv)

                if (item['flags'] & Manager.INVENTORY_FLAG_HOLD_FOREVER) == 0:
                    if inv.type == Inv.MSG_BLOCK:
                        if (now - item['time_added']) >= Manager.KEEP_BLOCK_IN_INVENTORY_TIME:
                            continue
                    elif inv.type == Inv.MSG_TX:
                        # If this tx is one that we produced, we hold onto it until it has enough confirmations
                        # If its a relayed transaction, we hold onto it for a period of time or until it's been broadcasted
                        # through enough peers.
                        if (item['flags'] & Manager.INVENTORY_FLAG_MUST_CONFIRM) != 0:
                            if self.spv.get_tx_depth(inv.hash) < self.spv.coin.TRANSACTION_CONFIRMATION_DEPTH:
                                continue

                            # If we want it confirmed and it was last relayed some time ago, rebroadcast
                            # by clearing the inv_to and sent_to sets.
                            if (now - item['last_time']) >= Manager.REBROADCAST_TRANSACTION_TIME:
                                item['sent_to'] = set()
                                item['inv_to'] = set()
                        else:
                            if (now - item['time_added']) >= Manager.KEEP_TRANSACTION_IN_INVENTORY_TIME:
                                if len(item['sent_to']) >= min(8, self.peer_goal):
                                    continue

                item['time_check'] = now

                self.inventory_items[inv] = item
                self.inventory.append(inv)

        self.last_manage_inventory_time = now

    def inventory_filter(self, peer_address, count=200):
        with self.inv_lock:
            r = []
            for inv in self.inventory:
                if len(r) == count:
                    break
                if peer_address not in self.inventory_items[inv]['inv_to']:
                    r.append(inv)
            return r

    def inventory_sent(self, peer_address, invs):
        with self.inv_lock:
            for inv in invs:
                if inv in self.inventory_items:
                    self.inventory_items[inv]['inv_to'].add(peer_address)

    def will_send_inventory(self, peer_address, inv):
        now = time.time()

        with self.inv_lock:
            if inv not in self.inventory_items:
                return Manager.REQUEST_DONT

            if peer_address in self.inventory_items[inv]:
                return Manager.REQUEST_DONT

            self.inventory_items[inv]['sent_to'].add(peer_address)
            self.inventory_items[inv]['last_sent'] = time.time()

            return Manager.REQUEST_GO

################################################################################
################################################################################
class Peer(threading.Thread):
    MAX_INVS_IN_PROGRESS = 10

    def __init__(self, manager, peer_address, sock=None):
        threading.Thread.__init__(self)
        self.manager = manager
        self.peer_address = peer_address
        self.socket = sock

    def shutdown(self):
        self.running = False

    def start(self):
        self.running = False
        threading.Thread.start(self)
        while not self.running:
            pass

    def run(self):
        self.state = 'init'
        self.running = True
        if self.manager.spv.logging_level <= DEBUG:
            print("[PEER] {} Peer starting...".format(self.peer_address))
        while self.running:
            try:
                self.step()
            except:
                traceback.print_exc()
                break
            time.sleep(0.1)
        if self.manager.spv.logging_level <= DEBUG:
            print("[PEER] {} Peer exiting ({} bytes recv/{} bytes sent)...".format(self.peer_address, self.bytes_received, self.bytes_sent))

    def step(self):
        if self.state == 'init':
            self.sent_version = False
            self.data_buffer = bytes()
            self.bytes_sent = 0
            self.bytes_received = 0
            self.last_data_time = time.time()
            self.last_block_time = time.time()
            self.inprogress_command = ''
            self.outgoing_data_queue = collections.deque()
            self.peer_verack = 0
            self.invs = {}
            self.inprogress_invs = {}
            self.handshake_time = None
            self.headers_request = None
            self.blocks_request = None
            self.syncing_blockchain = 1
            self.next_sync_time = 0
            self.last_inventory_check_time = time.time()
            self.requested_invs = collections.deque()
            if self.socket is None:
                if self.make_connection():
                    self.send_version()
                    self.state = 'connected'
            else:
                self.socket.settimeout(0.1)
                self.state = 'connected'
        elif self.state == 'connected':
            self.handle_outgoing_data()
            self.handle_incoming_data()
            self.handle_initial_blockchain_sync()
            self.handle_invs()
            self.handle_inventory()
        elif self.state == 'dead':
            self.close_connection()
            self.running = False

    def make_connection(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(5)

        try:
            self.socket.connect(self.peer_address)
            self.socket.settimeout(0.1)
            if self.manager.spv.logging_level <= DEBUG:
                print("[PEER] {} connected.".format(self.peer_address))
            return True
        except:
            self.state = 'dead'
            self.manager.peer_is_bad(self.peer_address)
            if self.manager.spv.logging_level <= DEBUG:
                print("[PEER] {} could not connect.".format(self.peer_address))
            return False

    def close_connection(self):
        try:
            if self.socket is not None:
                self.socket.close()
                self.socket = None
        except:
            # TODO :: catch the proper exception / close properly
            traceback.print_exc()

    def handle_incoming_data(self):
        try:
            data = self.socket.recv(4096)
            self.bytes_received += len(data)
        except ConnectionResetError:
            data = b''
        except socket.timeout:
            # Normal, no new data
            return

        # zero length data means we've lost connection
        if len(data) == 0: 
            if self.manager.spv.logging_level <= DEBUG:
                print("[PEER] {} connection lost.".format(self.peer_address))
            self.state = 'dead'
            return

        self.data_buffer = self.data_buffer + data
        self.last_data_time = time.time()

        while self.state != 'dead':
            command, payload, length, self.data_buffer = Serialize.unwrap_network_message(self.manager.spv.coin, self.data_buffer)
            self.inprogress_command = command

            if length is not None and length > Manager.MAX_MESSAGE_SIZE:
                if self.manager.spv.logging_level <= WARNING:
                    print("[PEER] {} sent a large message. dropping.".format(self.peer_address))
                self.state = 'dead'
                break

            if payload is None:
                break

            self.handle_command(command, payload)

    def handle_outgoing_data(self):
        while len(self.outgoing_data_queue) > 0:
            q = self.outgoing_data_queue.popleft()
            try:
                r = self.socket.send(q)
                self.bytes_sent += r
                if r < len(q):
                    self.outgoing_data_queue.appendleft(q[r:])
                    return
            except (ConnectionAbortedError, OSError):
                if self.manager.spv.logging_level <= DEBUG:
                    traceback.print_exc()
                self.state = 'dead'
                break

    def queue_outgoing_data(self, data):
        self.outgoing_data_queue.append(data)

    def handle_command(self, command, payload):
        # We only allow 'version' and 'verack' commands if we haven't finished handshake
        if self.peer_verack < 2 and command not in ('version', 'verack'):
            raise Exception("invalid command")

        try:
            cmd = getattr(self, 'cmd_' + command)
        except AttributeError:
            if self.manager.spv.logging_level <= WARNING:
                print('[PEER] {} unhandled command {}'.format(self.peer_address, command))
            return

        cmd(payload)

    def handle_initial_blockchain_sync(self):
        # Sync headers until we're within some window of blocks
        # of the creation date of our wallet. From that point forward
        # sync and process full blocks.
        #
        # Some magic happens here to make sure we're not just downloading
        # headers and blocks from a small group peers.

        if self.syncing_blockchain == 0:
            return

        now = time.time()

        if self.headers_request is not None:
            # Manager checks to see if our headers_request has timed out, so we don't need to.
            return

        if self.blocks_request is not None:
            if (now - self.blocks_request) > Manager.GETBLOCKS_REQUEST_TIMEOUT:
                # The only safe assumption we can make here is that the peer doesn't know about any more blocks. Thus, we have everything.
                self.blocks_request = None

                if self.syncing_blockchain == 2:
                    self.state = 'dead'
                    self.manager.peer_is_bad(self.peer_address)
                    if self.manager.spv.logging_level <= DEBUG:
                        print("[PEER] {} peer is messing with our blockchain sync".format(self.peer_address))
                else:
                    self.syncing_blockchain = 0
            return

        # Delay requests as necessary
        if time.time() < self.next_sync_time:
            return

        # Wait for a bit before requesting from peer
        if self.handshake_time is None or (time.time() - self.handshake_time) < Manager.BLOCKCHAIN_SYNC_WAIT_TIME:
            return

        # Requesting from peer wouldn't work, says the peer!
        if self.manager.spv.blockchain.get_best_chain_height() >= self.peer_last_block:
            return

        r = self.manager.will_request_headers(self)
        if r == Manager.REQUEST_GO:
            self.headers_request = time.time()
            self.send_getheaders(self.manager.spv.blockchain.get_best_chain_locator())
            return
        elif r == Manager.REQUEST_WAIT:
            # Manager wants to give another peer the chance to deliver headers
            self.next_sync_time = time.time() + 5
            return
        elif r == Manager.REQUEST_DONT:
            # We're done syncing headers. try getblocks...
            pass

        # We don't need to call getblocks if we know about any blocks
        # handle_invs will eventually request the blocks
        if any(inv.type == Inv.MSG_BLOCK for inv in self.invs.keys()):
            return

        r = self.manager.will_request_blocks()
        if r == Manager.REQUEST_GO:
            self.blocks_request = time.time()
            self.send_getblocks(self.manager.spv.blockchain.get_best_chain_locator())
            return
        elif r == Manager.REQUEST_WAIT:
            # We never really get here...
            self.next_sync_time = time.time() + 5
            return
        elif r == Manager.REQUEST_DONT:
            # Manager says so!
            pass

    def handle_invs(self):
        now = time.time()

        if len(self.inprogress_invs) > 0:
            inprogress_block_invs = [inv for inv in self.inprogress_invs if inv.type == Inv.MSG_BLOCK]
            if len(inprogress_block_invs):
                if self.inprogress_command != 'block' and (now - self.last_block_time) > Manager.BLOCK_REQUEST_TIMEOUT:
                    # Peer is ignoring our request for blocks...
                    if self.manager.spv.logging_level <= WARNING:
                        print('[PEER] {} peer is ignoring our request for blocks'.format(self.peer_address))
                    self.state = 'dead'
                    return

            # TODO - should we consider the peer misbehaving if its ignoring our request for transactions?
            inprogress_tx_invs = ((inv, when) for inv, when in self.inprogress_invs.items() if inv.type == Inv.MSG_TX)
            for inv, when in inprogress_tx_invs:
                if (now - when) > Manager.TX_REQUEST_TIMEOUT:
                    # Tell manager (by passing None) that the tx request timed out
                    self.manager.received_transaction(inv, None)
                    self.inprogress_invs.pop(inv)

            if len(self.inprogress_invs):
                return

        requests = set()
        aborts = set()

        # This loop prioritizes blocks
        for inv, when in sorted(self.invs.items(), key=lambda x: 1 if x[0].type == Inv.MSG_BLOCK else 2):
            if when > now:
                # This mechanism allows us to "retry" fetching the item later if one request fails
                continue
            
            res = self.manager.will_request_inv(inv)
            if res == Manager.REQUEST_GO:
                assert inv not in self.inprogress_invs
                requests.add(inv)
                self.invs[inv] = now + 2 # it'll get retried later if it doesn't get removed below
            elif res == Manager.REQUEST_DONT:
                aborts.add(inv)
            elif res == Manager.REQUEST_WAIT:
                self.invs[inv] = now + 5

            if len(requests) + len(self.inprogress_invs) >= Peer.MAX_INVS_IN_PROGRESS:
                break

        for inv in aborts:
            self.invs.pop(inv)

        for inv in self.request_invs(requests):
            self.invs.pop(inv)

    def request_invs(self, invs):
        if len(invs) != 0:
            now = time.time()
            for inv in invs:
                self.inprogress_invs[inv] = now
                yield inv
            self.send_getdata(invs)

    def handle_inventory(self):
        now = time.time()

        if len(self.requested_invs):
            # Queue up an inv if there isn't any other outgoing data
            if len(self.outgoing_data_queue):
                return

            for _ in range(len(self.requested_invs)):
                inv, when = self.requested_invs.popleft()
                r = self.manager.will_send_inventory(self.peer_address, inv)
                if r == Manager.REQUEST_GO:
                    data = self.manager.get_inventory_data(inv)
                    if data is None:
                        continue
                    if inv.type == Inv.MSG_TX:
                        self.send_tx(inv, data)
                    elif inv.type == Inv.MSG_BLOCK:
                        self.send_block(inv, data)
                    return
                elif r == Manager.REQUEST_WAIT:
                    self.requested_invs.append((inv, when + 3))
                    continue
                elif r == Manager.REQUEST_DONT:
                    continue
                
        if now < (self.last_inventory_check_time + Manager.INVENTORY_CHECK_TIME):
            return

        invs = self.manager.inventory_filter(self.peer_address)
        if len(invs):
            self.send_inv(invs)
            self.manager.inventory_sent(self.peer_address, invs)

        self.last_inventory_check_time = now

    def send_version(self):
        assert not self.sent_version, "don't call this twice"
        version  = Manager.PROTOCOL_VERSION
        services = Manager.SERVICES
        now      = int(time.time())

        recipient_address = Serialize.serialize_network_address(self.peer_address, services, with_timestamp=False)
        sender_address    = Serialize.serialize_network_address(None, services, with_timestamp=False)
        
        nonce      = random.randrange(0, 1 << 64)
        user_agent = Serialize.serialize_string(Manager.USER_AGENT)
        last_block = 0 # we aren't a full node...

        payload = struct.pack("<LQQ", version, services, now) + recipient_address + sender_address + struct.pack("<Q", nonce) + user_agent + struct.pack("<L", last_block)
        self.queue_outgoing_data(Serialize.wrap_network_message(self.manager.spv.coin, "version", payload))
        self.sent_version = True

    def send_verack(self):
        self.queue_outgoing_data(Serialize.wrap_network_message(self.manager.spv.coin, "verack", b''))

    def send_pong(self, payload):
        self.queue_outgoing_data(Serialize.wrap_network_message(self.manager.spv.coin, "pong", payload))

    def send_inv(self, invs):
        data = []
        data.append(Serialize.serialize_variable_int(len(invs)))
        for inv in invs:
            data.append(inv.serialize())

        payload = b''.join(data)
        self.queue_outgoing_data(Serialize.wrap_network_message(self.manager.spv.coin, "inv", payload))
        if self.manager.spv.logging_level <= DEBUG:
            print("[PEER] {} sent inv for {} items".format(self.peer_address, len(invs)))
        
    def send_getdata(self, invs):
        data = []
        for inv in invs:
            data.append(inv.serialize())

        payload = Serialize.serialize_variable_int(len(data)) + b''.join(data)
        self.queue_outgoing_data(Serialize.wrap_network_message(self.manager.spv.coin, "getdata", payload))
        if self.manager.spv.logging_level <= DEBUG:
            print("[PEER] {} sent getdata for {} items".format(self.peer_address, len(invs)))

    def send_getheaders(self, block_locator):
        last_block = (b'\x00' * 32)
        payload = struct.pack("<L", Manager.PROTOCOL_VERSION) + block_locator.serialize() + last_block

        self.queue_outgoing_data(Serialize.wrap_network_message(self.manager.spv.coin, "getheaders", payload))
        if self.manager.spv.logging_level <= DEBUG:
            print("[PEER] {} sent getheaders (block_locator top={})".format(self.peer_address, bytes_to_hexstring(block_locator.hashes[0])))

    def send_getblocks(self, block_locator):
        last_block = (b'\x00' * 32)
        payload = struct.pack("<L", Manager.PROTOCOL_VERSION) + block_locator.serialize() + last_block

        self.queue_outgoing_data(Serialize.wrap_network_message(self.manager.spv.coin, "getblocks", payload))
        if self.manager.spv.logging_level <= DEBUG:
            print("[PEER] {} sent getblocks".format(self.peer_address))

    def send_tx(self, inv, tx_data):
        self.queue_outgoing_data(Serialize.wrap_network_message(self.manager.spv.coin, "tx", tx_data))
        if self.manager.spv.logging_level <= DEBUG:
            print("[PEER] {} sent tx {}".format(self.peer_address, bytes_to_hexstring(inv.hash)))

    def send_block(self, inv, block_data):
        self.queue_outgoing_data(Serialize.wrap_network_message(self.manager.spv.coin, "block", block_data))
        if self.manager.spv.logging_level <= DEBUG:
            print("[PEER] {} sent block {}".format(self.peer_address, bytes_to_hexstring(inv.hash)))

    def send_addr(self, addresses):
        data = []
        for address in addresses:
            data.append(Serialize.serialize_network_address(address, Manager.SERVICES, with_timestamp=False))

        payload = Serialize.serialize_variable_int(len(addresses)) + b''.join(data)
        self.queue_outgoing_data(Serialize.wrap_network_message(self.manager.spv.coin, "addr", payload))
        if self.manager.spv.logging_level <= DEBUG:
            print("[PEER] {} sent addr for {} addresses".format(self.peer_address, len(addresses)))
        
    def cmd_version(self, payload):
        if len(payload) < 20:
            if self.manager.spv.logging_level <= WARNING:
                print('[PEER] {} sent badly formatted version command'.format(self.peer_address))
            self.state = 'dead'
            return

        self.peer_version = 0

        try:
            self.peer_version, self.peer_services, self.peer_time = struct.unpack("<LQQ", payload[:20])
            _, _, payload = Serialize.unserialize_network_address(payload[20:], with_timestamp=False)
            _, _, payload = Serialize.unserialize_network_address(payload, with_timestamp=False)
            nonce = struct.unpack("<Q", payload[:8])[0]
            self.peer_user_agent, payload = Serialize.unserialize_string(payload[8:])
            self.peer_last_block = struct.unpack("<L", payload)[0]
        except struct.error:
            # Not enough data usually
            self.state = 'dead'
            self.manager.peer_is_bad(self.peer_address)
            if self.manager.spv.logging_level <= DEBUG:
                print("[PEER] {} bad version {}".format(self.peer_address, self.peer_version))
            return

        if self.manager.spv.logging_level <= INFO:
            print("[PEER] {} version {} (User-agent {}, last block {})".format(self.peer_address, self.peer_version, self.peer_user_agent, self.peer_last_block))

        time_offset = abs(self.peer_time - time.time())
        if time_offset > 140*60:
            # Peer time is just too out of wack.
            if self.manager.spv.logging_level <= WARNING:
                print("[PEER] {} peer's clock (or yours!) is off by too much ({} sec)".format(self.peer_address, time_offset))
            self.state = 'dead'
            return

        # Let's only connect to peers that are fully synced.  If we connect to a syncing peer, it doesn't
        # really benefit us and it possibly harms them since we can't send them blocks.
        if self.peer_last_block < self.manager.spv.blockchain.get_best_chain_height():
            if self.manager.spv.logging_level <= INFO:
                print("[PEER] {} peer doesn't have a blockchain longer than ours".format(self.peer_address))
            self.state = 'dead'
            return

        self.send_verack()
        self.peer_verack += 1

        if not self.sent_version:
            self.send_version()

        if self.peer_verack == 2:
            self.manager.spv.add_time_data(self.peer_time)
            self.handshake_time = time.time()

    def cmd_verack(self, payload):
        self.peer_verack += 1

        if self.peer_verack == 2:
            self.manager.spv.add_time_data(self.peer_time)
            self.handshake_time = time.time()

    def cmd_ping(self, payload):
        self.send_pong(payload)

    def cmd_addr(self, payload):
        count, payload = Serialize.unserialize_variable_int(payload)

        for i in range(min(count, 1024)):
            addr, _, _, payload = Serialize.unserialize_network_address(payload, with_timestamp=self.peer_version >= 31402)
            self.manager.peer_found(addr)

    def cmd_inv(self, payload):
        count, payload = Serialize.unserialize_variable_int(payload)

        for i in range(count):
            inv, payload = Inv.unserialize(payload)

            if self.manager.spv.logging_level <= INFO:
                print('[PEER] {} got {}'.format(self.peer_address, str(inv)))

            if inv.type == Inv.MSG_BLOCK:
                # Doesn't matter if this was a getblocks request or
                # unsolicited. We now know about at least one block and should
                # fetch it before calling getblocks again.
                self.blocks_request = None

            if inv not in self.invs and inv not in self.inprogress_invs:
                self.invs[inv] = time.time()

    def cmd_tx(self, payload):
        tx, _ = Transaction.unserialize(payload, self.manager.spv.coin)
        tx_hash = tx.hash()
        inv = Inv(Inv.MSG_TX, tx_hash)

        if self.manager.spv.logging_level <= INFO:
            print("[PEER] {} got tx {}".format(self.peer_address, bytes_to_hexstring(inv.hash)))

        if inv in self.inprogress_invs:
            self.manager.received_transaction(inv, tx)
            self.inprogress_invs.pop(inv)
        else:
            raise Exception("peer sent a tx without us asking it to")

    def cmd_headers(self, payload):
        count, payload = Serialize.unserialize_variable_int(payload)

        headers = []
        for i in range(count):
            block_header, payload = BlockHeader.unserialize(payload, self.manager.spv.coin)
            headers.append(block_header)

            tx_count, payload = Serialize.unserialize_variable_int(payload)
            
            bad_peer = not block_header.check() or tx_count != 0
            if bad_peer:
                # Misbehaving peer: all headers are actually blocks with 0 transactions
                if self.manager.spv.logging_level <= WARNING:
                    print("[PEER] {} sent bad headers".format(self.peer_address, len(headers)))
                self.manager.peer_is_bad(self.peer_address)
                self.state = 'dead'
                return

        if self.manager.spv.logging_level <= INFO:
            print("[PEER] {} got {} headers".format(self.peer_address, len(headers)))
        
        if not self.manager.received_headers(headers):
            if len(headers) != 0:
                # Blockchain didn't accept our headers? bad...
                self.manager.peer_is_bad(self.peer_address)
                self.state = 'dead'
            
        self.headers_request = None

    def cmd_block(self, payload):
        block, payload = Block.unserialize(payload, self.manager.spv.coin)

        if not block.check():
            # peer sent a bad block?
            if self.manager.spv.logging_level <= WARNING:
                print("[PEER] {} peer sent bad block {}".format(self.peer_address, block))
            self.manager.peer_is_bad(self.peer_address)
            self.state = 'dead'
            return

        inv = Inv(Inv.MSG_BLOCK, block.header.hash())
        if inv in self.inprogress_invs:
            if self.manager.spv.logging_level <= INFO:
                print("[PEER] {} got {}".format(self.peer_address, block))
 
            self.manager.received_block(inv, block, self.syncing_blockchain != 0)
            self.inprogress_invs.pop(inv)
            self.last_block_time = time.time()

            # If we are not syncing from this peer and the peer sends us a block that doesn't connect,
            # we should try syncing again.  If the peer again doesn't send us blocks, we should disconnect.
            if self.syncing_blockchain == 0 and not self.manager.spv.blockchain.blocks[inv.hash]['connected']:
                self.syncing_blockchain = 2
        else:
            raise Exception("peer sent a block without us asking it to")

    def cmd_getdata(self, payload):
        count, payload = Serialize.unserialize_variable_int(payload)
        now = time.time()

        for _ in range(count):
            inv, payload = Inv.unserialize(payload)
            self.requested_invs.append((inv, now))

        if self.manager.spv.logging_level <= INFO:
            print('[PEER] {} requested {} items'.format(self.peer_address, count))

    def cmd_getblocks(self, payload):
        if self.manager.spv.logging_level <= DEBUG:
            print('[PEER] {} ignoring getblocks command'.format(self.peer_address))

    def cmd_getaddr(self, payload):
        # Select random addresses and send them
        peer_addresses = list(self.manager.peer_addresses.keys())
        random.shuffle(peer_addresses)
        peer_addresses = peer_addresses[:10]
        self.send_addr(peer_addresses)


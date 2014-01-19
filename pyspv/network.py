import collections
import ipaddress
import random
import socket
import struct
import threading
import time
import traceback

from .inv import Inv
from .serialize import Serialize
from .transaction import Transaction
from .util import *

DEFAULT_PORT = 8333

SEEDS = [
    'seed.bitcoin.sipa.be',
    'dnsseed.bluematt.me',
    'dnsseed.bitcoin.dashjr.org',
    'bitseed.xf2.org',
]
 
################################################################################
################################################################################
class OutOfPeers(Exception):
    pass

################################################################################
################################################################################
class MANAGER(threading.Thread):
    REQUEST_WAIT = 0
    REQUEST_GO = 1
    REQUEST_DONT = 2

    PEER_RECORD_SIZE = 14

    PROTOCOL_VERSION = 60002
    SERVICES = 1
    USER_AGENT = '/Satoshi:0.7.2/'

    def __init__(self, peer_goal=1, logging_level=WARNING):
        threading.Thread.__init__(self)
        self.peer_goal = peer_goal
        self.logging_level = logging_level

        self.peers = {}
        self.peer_addresses_db_file = "addresses.dat"
        self.peer_lock = threading.Lock()
        self.load_peer_addresses()

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
        for _, p in self.peers.items():
            p.join(*args, **kwargs)
        threading.Thread.join(self, *args, **kwargs)

    def run(self):
        self.running = True
        if self.logging_level <= DEBUG:
            print("[NETWORK] starting")
        while self.running:
            if len(self.peer_addresses) < 5:
                self.get_new_addresses_from_peer_sources()

            self.check_for_dead_peers()
            self.check_for_new_peers()

            time.sleep(0.001)
        if self.logging_level <= DEBUG:
            print("[NETWORK] stopping")

    def get_new_addresses_from_peer_sources(self):
        for seed in SEEDS:
            for _, _, _, _, ipport in socket.getaddrinfo(seed, None):
                if len(ipport) != 2: # no IPv6 support yet
                    continue
                ip, _ = ipport
                self.add_peer_address((ip, DEFAULT_PORT))

    def add_peer_address(self, peer_address):
        if peer_address in self.peer_addresses:
            return

        try:
            ipaddress.IPv4Address(peer_address[0]).packed
        except ipaddress.AddressValueError:
            # peer_address[0] is probably an IPv6 address
            if self.logging_level <= INFO:
                print("[NETWORK] peer address {} is not valid IPv4".format(peer_address[0]))
            return

        if self.logging_level <= DEBUG:
            print("[NETWORK] new peer found", peer_address)

        self.peer_addresses[peer_address] = {
            'last_successful_connection_time': 0.0,
            'index': self.peer_index,
        }

        self.update_peer_address(peer_address)

        self.peer_index += 1

    def update_peer_address(self, peer_address):
        if peer_address not in self.peer_addresses:
            return

        with open(self.peer_addresses_db_file, "ab") as fp:
            data = ipaddress.IPv4Address(peer_address[0]).packed + struct.pack("<Hd", peer_address[1], self.peer_addresses[peer_address]['last_successful_connection_time'])
            fp.seek(self.peer_addresses[peer_address]['index'] * MANAGER.PEER_RECORD_SIZE, 0)
            fp.write(data)

    def delete_peer_address(self, peer_address):
        if peer_address not in self.peer_addresses:
            return

        old = self.peer_addresses.pop(peer_address)
        self.peer_index -= 1

        with open(self.peer_addresses_db_file, "a+b") as fp:
            assert fp.tell() >= MANAGER.PEER_RECORD_SIZE  # This has to be true, since self.peer_addresses has at least one entry

            # When files are opened for append, they are positioned at the end of the file. Back up and read the final record, it'll be used to replace 'old'
            fp.seek(fp.tell()-MANAGER.PEER_RECORD_SIZE, 0) 
            data = fp.read(MANAGER.PEER_RECORD_SIZE)
            fp.truncate(self.peer_index * MANAGER.PEER_RECORD_SIZE)

            if old['index'] == (fp.tell() // MANAGER.PEER_RECORD_SIZE):
                return

            port, _ = struct.unpack("<Hd", data[4:])
            peer_address = (ipaddress.IPv4Address(data[0:4]).exploded, port)
            self.peer_addresses[peer_address]['index'] = old['index']
            fp.seek(old['index'] * MANAGER.PEER_RECORD_SIZE)
            fp.write(data)
            
    def load_peer_addresses(self):
        self.peer_addresses = {}
        self.peer_index = 0
        try:
            with open(self.peer_addresses_db_file, "rb") as fp:
                while True:
                    data = fp.read(MANAGER.PEER_RECORD_SIZE)
                    if len(data) == 0:
                        break
                    port, last = struct.unpack("<Hd", data[4:])
                    peer_address = (ipaddress.IPv4Address(data[0:4]).exploded, port)
                    self.peer_addresses[peer_address] = {
                        'last_successful_connection_time': last,
                        'index': self.peer_index,
                    }
                    self.peer_index += 1
            if self.logging_level <= DEBUG:
                print("[NETWORK] {} peer addresses loaded".format(len(self.peer_addresses)))
        except FileNotFoundError:
            pass

    def check_for_dead_peers(self):
        dead_peers = set()

        for peer_address, peer in self.peers.items():
            if peer.is_alive():
                continue
            dead_peers.add(peer_address)

        for peer_address in dead_peers:
            peer = self.peers.pop(peer_address)
 
    def check_for_new_peers(self):
        try:
            while len(self.peers) < self.peer_goal:
                self.start_new_peer()
        except OutOfPeers:
            # TODO - handle out of peers case
            if self.logging_level <= WARNING:
                traceback.print_exc()
        
    def start_new_peer(self):
        peer_addresses = list(self.peer_addresses.keys())
        while len(peer_addresses) > 0:
            k = random.randrange(0, len(peer_addresses))
            p, peer_addresses = peer_addresses[k], peer_addresses[:k] + peer_addresses[k+1:]
            if p not in self.peers:
                self.peers[p] = PEER(self, p)
                self.peers[p].start()
                break
        else:
            raise OutOfPeers()

    def peer_is_bad(self, peer_address):
        with self.peer_lock:
            self.delete_peer_address(peer_address)

    def peer_is_good(self, peer_address):
        p = self.peer_addresses.get(peer_address, None)
        if p is not None:
            p['last_successful_connection_time'] = time.time()
            with self.peer_lock:
                self.update_peer_address(peer_address)

    def peer_found(self, peer_address):
        with self.peer_lock:
            self.add_peer_address(peer_address)

    def will_request_inv(self, inv):
        return MANAGER.REQUEST_GO

    def received_transaction(self, tx):
        pass

    def received_block(self, block):
        pass

################################################################################
################################################################################
class PEER(threading.Thread):
    MAX_INVS_IN_PROGRESS = 3

    def __init__(self, manager, peer_address):
        threading.Thread.__init__(self)
        self.manager = manager
        self.peer_address = peer_address

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
        if self.manager.logging_level <= DEBUG:
            print("[PEER] {} Peer starting...".format(self.peer_address))
        while self.running:
            try:
                self.step()
            except:
                traceback.print_exc()
                break
            time.sleep(0.1)
        if self.manager.logging_level <= DEBUG:
            print("[PEER] {} Peer exiting ({} bytes recv/{} bytes sent)...".format(self.peer_address, self.bytes_received, self.bytes_sent))

    def step(self):
        if self.state == 'init':
            self.data_buffer = bytes()
            self.bytes_sent = 0
            self.bytes_received = 0
            self.outgoing_data_queue = collections.deque()
            self.peer_verack = 0
            self.invs = {}
            self.inprogress_invs = {}
            if self.make_connection():
                self.send_version()
                self.state = 'connected'
        elif self.state == 'connected':
            self.handle_outgoing_data()
            self.handle_incoming_data()
            self.handle_invs()
        elif self.state == 'dead':
            self.running = False

    def make_connection(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(5)

        try:
            self.socket.connect(self.peer_address)
            self.socket.settimeout(0.1)
            if self.manager.logging_level <= DEBUG:
                print("[PEER] {} connected.".format(self.peer_address))
            return True
        except:
            self.state = 'dead'
            self.manager.peer_is_bad(self.peer_address)
            if self.manager.logging_level <= DEBUG:
                print("[PEER] {} could not connect.".format(self.peer_address))
            return False

    def handle_incoming_data(self):
        try:
            data = self.socket.recv(4096)
            self.bytes_received += len(data)
        except socket.timeout:
            # Normal, no new data
            return

        # zero length data means we've lost connection
        if len(data) == 0: 
            if self.manager.logging_level <= DEBUG:
                print("[PEER] {} connection lost.".format(self.peer_address))
            self.state = 'dead'
            return

        self.data_buffer = self.data_buffer + data

        while self.state != 'dead':
            command, payload, self.data_buffer = Serialize.unwrap_network_message(self.data_buffer)

            if command is None:
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
                if self.manager.logging_level <= DEBUG:
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
            if self.manager.logging_level <= WARNING:
                print('[PEER] {} unhandled command {}'.format(self.peer_address, command))
            return

        cmd(payload)

    def handle_invs(self):
        if len(self.inprogress_invs) >= PEER.MAX_INVS_IN_PROGRESS:
            # TODO - remove invs that have not gotten any data (we need to distinguish from
            # not getting any data vs. a large block taking more than x time to download)
            return

        now = time.time()
        requests = set()
        aborts = set()

        for inv, when in self.invs.items():
            if when > now:
                # This mechanism allows us to "retry" fetching the item later if one request fails
                continue
            
            # TODO - handle blocks
            if inv.type == Inv.MSG_BLOCK:
                aborts.add(inv)
                continue

            res = self.manager.will_request_inv(inv)
            if res == MANAGER.REQUEST_GO:
                assert inv not in self.inprogress_invs
                requests.add(inv)
                self.invs[inv] = now + 2 # it'll get retried later if it doesn't get removed below
            elif res == MANAGER.REQUEST_DONT:
                aborts.add(inv)
            elif res == MANAGER.REQUEST_WAIT:
                self.invs[inv] = now + 5

            if len(requests) + len(self.inprogress_invs) >= PEER.MAX_INVS_IN_PROGRESS:
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

    def send_version(self):
        version  = MANAGER.PROTOCOL_VERSION
        services = MANAGER.SERVICES
        now      = int(time.time())

        recipient_address = Serialize.serialize_network_address(self.peer_address, services, with_timestamp=False)
        sender_address    = Serialize.serialize_network_address(None, services, with_timestamp=False)
        
        nonce      = random.randrange(0, 1 << 64)
        user_agent = Serialize.serialize_string(MANAGER.USER_AGENT)
        last_block = 0 # TODO blockchain.get_height()

        payload = struct.pack("<LQQ", version, services, now) + recipient_address + sender_address + struct.pack("<Q", nonce) + user_agent + struct.pack("<L", last_block)
        self.queue_outgoing_data(Serialize.wrap_network_message("version", payload))

    def send_verack(self):
        self.queue_outgoing_data(Serialize.wrap_network_message("verack", b''))

    def send_getdata(self, invs):
        data = []
        for inv in invs:
            data.append(inv.serialize())

        payload = Serialize.serialize_variable_int(len(data)) + b''.join(data)
        self.queue_outgoing_data(Serialize.wrap_network_message("getdata", payload))
        if self.manager.logging_level <= DEBUG:
            print("[PEER] {} sent getdata for {} items".format(self.peer_address, len(invs)))

    def cmd_version(self, payload):
        if len(payload) < 20:
            if self.manager.logging_level <= WARNING:
                print('[PEER] {} sent badly formatted version command'.format(self.peer_address))
            self.state = 'dead'
            return

        try:
            self.peer_version, self.peer_services, _ = struct.unpack("<LQQ", payload[:20])
            _, _, payload = Serialize.unserialize_network_address(payload[20:], with_timestamp=False)
            _, _, payload = Serialize.unserialize_network_address(payload, with_timestamp=False)
            nonce = struct.unpack("<Q", payload[:8])[0]
            self.peer_user_agent, payload = Serialize.unserialize_string(payload[8:])
            self.peer_last_block = struct.unpack("<L", payload)[0]
        except struct.error:
            # Not enough data usually
            self.state = 'dead'
            self.manager.peer_is_bad(self.peer_address)
            if self.manager.logging_level <= DEBUG:
                print("[PEER] {} bad version.".format(self.peer_address))
            return

        if self.manager.logging_level <= INFO:
            print("[PEER] {} version {} (User-agent {}, last block {})".format(self.peer_address, self.peer_version, self.peer_user_agent, self.peer_last_block))
        self.send_verack()
        self.peer_verack += 1

    def cmd_verack(self, payload):
        self.peer_verack += 1

    def cmd_addr(self, payload):
        count, payload = Serialize.unserialize_variable_int(payload)

        for i in range(min(count, 1024)):
            addr, _, _, payload = Serialize.unserialize_network_address(payload, with_timestamp=self.peer_version >= 31402)
            self.manager.peer_found(addr)

    def cmd_inv(self, payload):
        count, payload = Serialize.unserialize_variable_int(payload)

        for i in range(count):
            inv, payload = Inv.unserialize(payload)

            if inv.type == Inv.MSG_ERROR:
                if self.manager.logging_level <= INFO:
                    print('[PEER] {} inv error {}'.format(self.peer_address, bytes_to_hexstring(inv.hash)))

            elif inv.type == Inv.MSG_TX:
                if self.manager.logging_level <= INFO:
                    print('[PEER] {} inv tx {}'.format(self.peer_address, bytes_to_hexstring(inv.hash)))

            elif inv.type == Inv.MSG_BLOCK:
                if self.manager.logging_level <= INFO:
                    print('[PEER] {} inv block {}'.format(self.peer_address, bytes_to_hexstring(inv.hash)))
                #!key = (inv, time.time())
                #!self.known_blocks_order[self.known_blocks_order_index] = key
                #!self.known_blocks_order_index += 1

            if inv not in self.invs and inv not in self.inprogress_invs:
                self.invs[inv] = time.time()

        # We can reset the getblocks if we have gotten a response...
        #! if len(self.known_blocks) >= 50:
        #!     self.last_get_blocks_time = 0

    def cmd_tx(self, payload):
        tx, _ = Transaction.unserialize(payload)
        tx_hash = tx.hash()
        inv = Inv(Inv.MSG_TX, tx_hash)
        if inv in self.inprogress_invs:
            print(str(tx))
            self.manager.received_transaction(tx)
            self.inprogress_invs.pop(inv)
        else:
            raise Exception("peer sent a tx without us asking it to")


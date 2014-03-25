import collections
import os
import shelve
import threading
import time

from contextlib import closing

from .block import Block, BlockHeader
from .serialize import Serialize
from .script import Script
from .util import *

class Blockchain:
    SAVED_BLOCKCHAIN_LENGTH = 100

    def __init__(self, spv):
        assert (spv.coin.CHECKPOINT_BLOCK_HEIGHT % spv.coin.WORK_INTERVAL) == 0

        self.spv = spv
        self.saved_blockchain_length = max(Blockchain.SAVED_BLOCKCHAIN_LENGTH, self.spv.coin.WORK_INTERVAL) # Save at least WORK_INTERVAL blocks

        self.blockchain_db_file = spv.config.get_file("blockchain")
        self.blockchain_lock = threading.Lock() # TODO use RLock?

        genesis = self.create_block_link(hash=self.spv.coin.GENESIS_BLOCK_HASH, height=0, main=True, connected=True, header=BlockHeader(spv.coin, timestamp=self.spv.coin.GENESIS_BLOCK_TIMESTAMP, bits=self.spv.coin.GENESIS_BLOCK_BITS))
        checkpoint = self.create_block_link(hash=self.spv.coin.CHECKPOINT_BLOCK_HASH, height=self.spv.coin.CHECKPOINT_BLOCK_HEIGHT, main=True, connected=True, header=BlockHeader(spv.coin, timestamp=self.spv.coin.CHECKPOINT_BLOCK_TIMESTAMP, bits=self.spv.coin.CHECKPOINT_BLOCK_BITS))

        self.blocks = {
            self.spv.coin.GENESIS_BLOCK_HASH   : genesis,
            self.spv.coin.CHECKPOINT_BLOCK_HASH: checkpoint,
        }

        self.unknown_referenced_blocks = collections.defaultdict(set)

        with self.blockchain_lock:
            with closing(shelve.open(self.blockchain_db_file)) as db:
                if 'needs_headers' not in db or self.spv.args.resync:
                    db['needs_headers'] = True

                # Make sure sync_block_start is consistent between restarts
                if 'sync_block_start' not in db:
                    db['sync_block_start'] = None

                if self.spv.sync_block_start is not None:
                    db['sync_block_start'] = self.spv.sync_block_start

                self.sync_block_start = db['sync_block_start']
                self.best_chain = (checkpoint if (self.sync_block_start is None or self.sync_block_start >= checkpoint['height']) else genesis)

                if 'blockchain' not in db or self.spv.args.resync:
                    db['blockchain'] = {
                        'start': 0,
                        'count': 0,
                        'links': [None] * self.saved_blockchain_length,
                    }

                self.needs_headers = db['needs_headers']

                # load blocks from db
                start = db['blockchain']['start']
                links = db['blockchain']['links']

                start_time = time.time()
                if self.spv.logging_level <= INFO:
                    print('[BLOCKCHAIN] loading blockchain headers...')

                for i in range(db['blockchain']['count']):
                    index = (start + i) % self.saved_blockchain_length
                    link = links[index]
                    #print('connecting {}/{}, {}'.format(i, db['blockchain']['count'], bytes_to_hexstring(link['hash'])))

                    header, _ = BlockHeader.unserialize(link['header'], self.spv.coin)
                    block_link = self.create_block_link(header.hash(), height=link['height'], work=link['work'], header=header)

                    # changes are ignored when loading
                    self.__connect_block_link(None, block_link, skip_validation=True)

                    # First block has to be manually connected. The rest of the blocks will connect normally
                    if i == 0:
                        block_link['connected'] = True
                        block_link['main'] = True
                        block_link['height'] = link['height']
                        self.best_chain = block_link
                    else:
                        if self.best_chain is not block_link:
                            #print("Error connecting block {}".format(str(block_link['header'])))#bytes_to_hexstring(block_link['hash'])))
                            #print("best block is {}".format(str(self.best_chain['header'])))#bytes_to_hexstring(self.best_chain['hash'])))
                            raise Exception("Uh oh. Blockchain state is corrupted. Loaded {} blocks to height {}.".format(i, self.best_chain['height']))

                if self.spv.logging_level <= INFO:
                    print('[BLOCKCHAIN] done ({:5.3f} sec)'.format(time.time()-start_time))

    def create_block_link(self, hash, height=0, main=False, connected=False, prev=None, header=None, work=None):
        if work is None and header is not None:
            work = header.work()
        else:
            work = 0

        return {
            'hash'     : hash,
            'height'   : height,
            'main'     : main,
            'connected': connected,
            'prev'     : prev,
            'header'   : header,
            'work'     : work,
        }

    def get_best_chain_locator(self):
        return BlockLocator(self.best_chain)

    def get_best_chain_height(self):
        return self.best_chain['height']

    def get_needs_headers(self):
        with self.blockchain_lock:
            return self.needs_headers

    def add_block_headers(self, block_headers):
        # The incoming headers must ALL connect, but they are allowed to disconnect some blocks
        # before connecting into the chain.
        if len(block_headers) == 0:
            print('no headers')
            return False

        # First, link all the block_headers that were given
        new_block_links = []
        new_block_links.append(self.create_block_link(hash=block_headers[0].hash(), header=block_headers[0]))

        for i in range(1, len(block_headers)):
            new_block_links.append(self.create_block_link(hash=block_headers[i].hash(), header=block_headers[i]))

            if block_headers[i].prev_block_hash != new_block_links[i-1]['hash']:
                # The chain of headers we were just given doesn't connect to eachother
                return False

            new_block_links[i]['prev'] = new_block_links[i-1]

        changes = []
        with self.blockchain_lock:
            if not self.needs_headers:
                print('doesnt need headers')
                return False

            # All of the blocks must be new
            if any(block_link['hash'] in self.blocks for block_link in new_block_links):
                print('seen some of the block headers before')
                return False

            # make sure the first block connects
            prev = self.blocks.get(block_headers[0].prev_block_hash, None)
            if prev is None:
                print('first block doesnt connect')
                return False

            with closing(shelve.open(self.blockchain_db_file)) as db:
                blockchain = db['blockchain'].copy()

                # Connect it and update the rest of the blocks
                new_block_links[0]['prev'] = prev

                for new_block_link in new_block_links:
                    changes = changes + self.__connect_block_link(blockchain, new_block_link)
                    assert self.best_chain is new_block_link

                    if (self.best_chain['header'].timestamp >= self.spv.wallet.creation_time - (24 * 60 * 60)) or (self.sync_block_start is not None and self.best_chain['height'] >= self.sync_block_start):
                        print('headers sync done, switching to full blocks')
                        self.needs_headers = db['needs_headers'] = False
                        break

                db['blockchain'] = blockchain

            self.__run_changes(changes)

        if self.spv.logging_level <= INFO:
            print("[BLOCKCHAIN] added {} headers (new height = {})".format(len(new_block_links), self.best_chain['height']))

        return True

    def add_block(self, block):
        if not block.check():
            return

        block_link = self.create_block_link(hash=block.header.hash(), header=block.header)

        # __connect_block_link drops the block data after its connected to the block tree
        block_link['block'] = block

        with self.blockchain_lock:
            with closing(shelve.open(self.blockchain_db_file)) as db:
                blockchain = db['blockchain'].copy()
                changes = self.__connect_block_link(blockchain, block_link)
                db['blockchain'] = blockchain

            self.__run_changes(changes)

    def __run_changes(self, changes):
        for change in changes:
            if change[0] == 'removed':
                self.spv.on_block_removed(*change[1:])
            elif change[0] == 'added':
                self.spv.on_block_added(*change[1:])

    def __connect_block_link(self, blockchain, block_link, skip_validation=False):
        changes = []

        if block_link['hash'] in self.blocks: 
            if self.spv.logging_level <= DEBUG:
                print("[BLOCKCHAIN] already have {}".format(bytes_to_hexstring(block_link['hash'])))
            return []

        self.blocks[block_link['hash']] = block_link
        self.unknown_referenced_blocks[block_link['header'].prev_block_hash].add(block_link['hash'])

        # See if this block causes any chains to be created or extended
        hashes_to_check = collections.deque([block_link['header'].prev_block_hash])
        while len(hashes_to_check) != 0:
            hash_to_check = hashes_to_check.popleft()

            if hash_to_check not in self.unknown_referenced_blocks or hash_to_check not in self.blocks or not self.blocks[hash_to_check]['connected']:
                continue
            
            for referenced_by_block_hash in self.unknown_referenced_blocks.pop(hash_to_check):
                referenced_by_block_link = self.blocks[referenced_by_block_hash]
                assert referenced_by_block_link['header'].prev_block_hash == hash_to_check
                assert not referenced_by_block_link['connected']

                error = None
                height = self.blocks[hash_to_check]['height'] + 1
                block_time = referenced_by_block_link['header'].timestamp

                # The block must meet proof of work requirements
                while not skip_validation:
                    next_work = self.__get_next_work(self.blocks[hash_to_check], referenced_by_block_link['header'].timestamp)
                    if next_work != referenced_by_block_link['header'].bits:
                        error = "proof of work error: new block has bits = {:x} but it should be {:x}".format(referenced_by_block_link['header'].bits, next_work)
                        break

                    # The block timestamp must be at least after the previous block timestamp minus the median block time
                    if referenced_by_block_link['header'].timestamp <= self.__get_median_time_past(self.blocks[hash_to_check]):
                        error = "timestamp error: new block has timestamp = {} but it should be less than {}".format(referenced_by_block_link['header'].timestamp, self.__get_median_time_past(self.blocks[hash_to_check]))
                        break

                    # All transactions in the block have to be final
                    block = referenced_by_block_link.get('block', None)
                    if block is not None:
                        if not all(tx.is_final(height, block_time) for tx in block.transactions):
                            error = "not all transactions in block are final"
                            break

                        # Reject version 2 and higher blocks if at least 750 of the past 1000 blocks are version 2 or later and
                        # if the coinbase doesn't start with the serialized block height
                        if referenced_by_block_link['header'].version >= 2:
                            if (not self.spv.testnet and self.__is_block_majority(2, self.blocks[hash_to_check], 750, 1000)) or \
                                    (self.spv.testnet and self.__is_block_majority(2, self.blocks[hash_to_check], 51, 100)):

                                v = []
                                t = height
                                while t != 0:
                                    v.append(t % 256)
                                    t //= 256

                                s = Script()
                                s.push_bytes(bytes(v))
                                s = s.serialize()

                                coinbase_script = block.transactions[0].inputs[0].script
                                if coinbase_script.serialize()[:len(s)] != s:
                                    error = "coinbase doesn't have encoded block height"
                                    break

                    # Reject version 1 blocks if at least 950 of the past 1000 blocks are version 2 or later
                    if referenced_by_block_link['header'].version < 2:
                        if (not self.spv.testnet and self.__is_block_majority(2, self.blocks[hash_to_check], 950, 1000)) or \
                                (self.spv.testnet and self.__is_block_majority(2, self.blocks[hash_to_check], 75, 100)):
                            error = "block should not be version 1"
                            break
                    
                    break

                if error is None:
                    if 'block' in referenced_by_block_link:
                        # Save memory: we don't need the transactions anymore
                        referenced_by_block_link.pop('block')
                    referenced_by_block_link['prev'] = self.blocks[hash_to_check]
                    referenced_by_block_link['height'] = self.blocks[hash_to_check]['height'] + 1
                    referenced_by_block_link['connected'] = True
                    referenced_by_block_link['main'] = False
                    referenced_by_block_link['work'] = self.blocks[hash_to_check]['work'] + referenced_by_block_link['header'].work()

                    changes = changes + self.__set_best_chain(blockchain, referenced_by_block_link)
                    hashes_to_check.append(referenced_by_block_hash)
                else:
                    # This block is bad. Remove it from everything.
                    print('[BLOCKCHAIN] invalid block {}: {}'.format(bytes_to_hexstring(referenced_by_block_hash), error))

                    self.blocks.pop(referenced_by_block_hash)

                    if referenced_by_block_hash in self.unknown_referenced_blocks:
                        self.unknown_referenced_blocks.pop(referenced_by_block_hash)

        if self.spv.logging_level <= INFO and not block_link['connected'] and blockchain is not None:
            # TODO Should we store orphaned blocks on disk so that they aren't fetched from the network
            # upon restarting?
            print("[BLOCKCHAIN] orphaned {}".format(bytes_to_hexstring(block_link['hash'])))

        return changes

    def get_next_work(self, next_block_link_timestamp):
        with self.blockchain_lock:
            return self.__get_next_work(self.best_chain, next_block_link_timestamp)

    def get_next_reward(self):
        return self.spv.coin.STARTING_BLOCK_REWARD >> ((self.best_chain['height'] + 1) // self.spv.coin.BLOCK_REWARD_HALVING)

    def __get_next_work(self, prev_block_link, next_block_link_timestamp):
        if ((prev_block_link['height'] + 1) % self.spv.coin.WORK_INTERVAL) != 0:
            # special retargetting rules for testnet
            if self.spv.testnet:
                if next_block_link_timestamp > (prev_block_link['header'].timestamp + (self.spv.coin.TARGET_BLOCK_SPACING * 2)):
                    return target_to_bits(Block.BLOCK_DIFFICULTY_LIMIT)
                else:
                    # return the last block that did not fall under the special min-difficulty rule
                    p = prev_block_link
                    bits_limit = target_to_bits(Block.BLOCK_DIFFICULTY_LIMIT)
                    while p['prev'] is not None and (p['height'] % self.spv.coin.WORK_INTERVAL) != 0 and p['header'].bits == bits_limit:
                        p = p['prev']
                    return p['header'].bits
            else:
                return prev_block_link['header'].bits

        # Get the block at the beginning of the adjustment interval
        p = prev_block_link
        for _ in range(self.spv.coin.WORK_INTERVAL - 1):
            p = p['prev']
            if p is None:
                raise Exception("There are not enough blocks in our blockchain to compute proof of work. That's a problem")

        # Clamp target to limited range
        timespan = prev_block_link['header'].timestamp - p['header'].timestamp
        timespan = max(timespan, self.spv.coin.TARGET_BLOCK_TIMESPAN // 4)
        timespan = min(timespan, self.spv.coin.TARGET_BLOCK_TIMESPAN * 4)

        target = bits_to_target(prev_block_link['header'].bits) * timespan
        target = target // self.spv.coin.TARGET_BLOCK_TIMESPAN
        target = min(target, Block.BLOCK_DIFFICULTY_LIMIT)

        bits = target_to_bits(target)

        if self.spv.logging_level <= DEBUG:
            print("[BLOCKCHAIN] block work retarget!!")
            print("[BLOCKCHAIN]     target timespan = {}    actual timespan = {}".format(self.spv.coin.TARGET_BLOCK_TIMESPAN, timespan))
            print("[BLOCKCHAIN]     before: {:08x}  {:064x}".format(prev_block_link['header'].bits, bits_to_target(prev_block_link['header'].bits)))
            print("[BLOCKCHAIN]     after:  {:08x}  {:064x}  change: {:5.3f}%".format(bits, bits_to_target(bits), (target - bits_to_target(prev_block_link['header'].bits)) / bits_to_target(prev_block_link['header'].bits) * 100))

        return bits

    def __get_median_time_past(self, block_link):
        if 'median_time_past' in block_link:
            return block_link['median_time_past']

        times = []
        p = block_link
        for _ in range(self.spv.coin.MEDIAN_TIME_SPAN):
            times.append(p['header'].timestamp)
            p = p['prev']
            if p is None:
                break

        times.sort()
        block_link['median_time_past'] = times[len(times)//2]
        return block_link['median_time_past']

    def __is_block_majority(self, min_version, block_link_start, target_block_count, block_population_count):
        found = 0

        for _ in range(block_population_count):
            if block_link_start['header'].version >= min_version:
                found += 1
            block_link_start = block_link_start['prev']
            if block_link_start is None:
                break

        return found >= target_block_count

    def __set_best_chain(self, blockchain, block_link):
        assert block_link['connected']
        changes = []

        # New block has to have more work
        if block_link['work'] <= self.best_chain['work']:
            return []

        new_best_chain = block_link
        old_best_chain = self.best_chain
        self.best_chain = new_best_chain

        # Old chain being longer is actually a rare case 
        while old_best_chain['height'] > new_best_chain['height']:
            if blockchain is not None:
                # drop count by one and notify SPV that a block was removed from the chain
                count = blockchain['count']
                count -= 1
                assert count >= 0, "this is bad."
                blockchain['count'] = count

            changes.append(('removed', old_best_chain['header'], old_best_chain['height']))
            old_best_chain['main'] = False
            old_best_chain = old_best_chain['prev']

        while new_best_chain['height'] > old_best_chain['height']:
            new_best_chain['main'] = True
            new_best_chain = new_best_chain['prev']
 
        # At this point, new_best_chain['height'] == old_best_chain['height']
        assert new_best_chain['height'] == old_best_chain['height']

        if new_best_chain is not old_best_chain:
            while new_best_chain['hash'] != old_best_chain['hash']:
                if blockchain is not None:
                    # drop count by one and notify SPV that a block was removed from the chain
                    count = blockchain['count']
                    count -= 1
                    assert count >= 0, "this is bad."
                    blockchain['count'] = count

                changes.append(('removed', old_best_chain['header'], old_best_chain['height']))
                old_best_chain['main'] = False
                old_best_chain = old_best_chain['prev']

                new_best_chain['main'] = True
                new_best_chain = new_best_chain['prev']
        
        # add the new chain (in order) and notify spv
        notify_block_links = []
        chain_fork = new_best_chain
        end_fork = self.best_chain
        while end_fork is not chain_fork:
            notify_block_links.append(end_fork)
            end_fork = end_fork['prev']

        while len(notify_block_links):
            notify_block_link = notify_block_links.pop()
            if blockchain is not None:
                start = blockchain['start']
                count = blockchain['count']

                index = (start + count) % self.saved_blockchain_length

                links = blockchain['links']
                links[index] = {
                    'work'  : notify_block_link['work'],
                    'height': notify_block_link['height'],
                    'hash'  : notify_block_link['hash'],
                    'header': notify_block_link['header'].serialize(),
                }

                if count != self.saved_blockchain_length:
                    count += 1
                    blockchain['count'] = count
                else:
                    start = (start + 1) % self.saved_blockchain_length

                blockchain['start'] = start
                blockchain['links'] = links

            changes.append(('added', notify_block_link['header'], notify_block_link['height']))

        if self.spv.logging_level <= INFO and blockchain is not None:
            print('[BLOCKCHAIN] new best chain = {} (height={})'.format(bytes_to_hexstring(self.best_chain['hash']), self.best_chain['height']))
 
        return changes

class BlockLocator:
    def __init__(self, block_link):
        self.hashes = [block_link['hash']]

        step = 1
        while block_link['prev'] is not None:
            if len(self.hashes) >= 10:
                step *= 2
            for _ in range(step):
                if block_link['prev'] is None:
                    break
                block_link = block_link['prev']
            self.hashes.append(block_link['hash'])

    def serialize(self):
        return Serialize.serialize_variable_int(len(self.hashes)) + b''.join(self.hashes)

    def __str__(self):
        return '<block_locator\n\t' + '\n\t'.join(['{}'.format(bytes_to_hexstring(block_hash)) for block_hash in self.hashes][::-1]) + '>'



import random

from .keys import PrivateKey
from .script import Script
from .transaction import Transaction, TransactionOutput, UnsignedTransactionInput, TransactionTooExpensive

from .util import *

class InsufficientInputs(Exception):
    pass

class TransactionBuilder:
    def __init__(self, spv, lock_time=0, memo=''):
        self.spv = spv
        self.memo = memo
        self.outputs = []
        self.lock_time = lock_time
        self.included_spends = []

    def process(self, output_producer):
        output_set = []
        for output in output_producer.create_outputs(self.spv):
            assert isinstance(output, TransactionOutput)
            output_set.append(output)
        self.outputs.append((False, output_set))

    def process_change(self, change_class):
        self.outputs.append((True, change_class))
        
    def __unsigned_inputs_from_spends(self, spends):
        inputs = []
        included_spend_flags = { included_spend['spend_hash']: included_spend['hash_flags'] for included_spend in self.included_spends }
        for spend in spends:
            spend_hash = spend.hash()
            hash_flags = included_spend_flags.get(spend_hash, Transaction.SIGHASH_ALL)
            for input_creator in spend.create_input_creators(self.spv, hash_flags):
                inputs.append(UnsignedTransactionInput(input_creator))
        return inputs

    def include_spend(self, spend_hash, anyone_can_pay=False, output_hash_type=Transaction.SIGHASH_ALL):
        '''include_spend forces the inclusion of the specified spend as an input into this transaction.

        :param anyone_can_pay: set to True if you want to allow other inputs to be added to this transaction
        :type anyone_can_pay: boolean
        :param output_hash_type: specifies whether to include all or no outputs as part of the signature for this input
        :type output_hash_type: SIGHASH_ALL or SIGHASH_NONE
        '''
        assert output_hash_type in (Transaction.SIGHASH_NONE, Transaction.SIGHASH_ALL)
        self.included_spends.append({
            'spend_hash': spend_hash, 
            'spend'     : self.spv.wallet.spends[spend_hash]['spend'],
            'hash_flags': output_hash_type | (Transaction.SIGHASH_ANYONECANPAY if anyone_can_pay else 0)
        })

    def include_spend_to_output(self, spend_hash, output_producer):
        '''Only valid if this spend produces the same number of inputs as the specified output produces outputs, and if they come first in the transaction'''
        # TODO
        pass

    def select_spends(self):
        '''Select spends from the wallet to provide enough coins into this transaction to make it valid'''
        # TODO
        pass

    def finish(self, shuffle_inputs, shuffle_outputs, allow_unpaid=False, force_fee=None):
        # TODO allow_unpaid
        # TODO force_fee
        if shuffle_outputs:
            random.shuffle(self.outputs)

        outputs = []
        change_outputs = []
        for is_change, output_set in self.outputs:
            if not is_change:
                outputs = outputs + output_set
                continue

            # All change outputs start at 0
            change_output = output_set().create_one(self.spv)
            change_output.amount = 0
            change_outputs.append(change_output)
            outputs.append(change_output)

        assert len(change_outputs) == 1 # right now only 1 change address supported

        # determine the total inputs and outputs
        included_spends = [included_spend['spend'] for included_spend in self.included_spends]
        included_spend_amount = sum(spend.amount for spend in included_spends)
        included_spend_hashes = set(included_spend['spend_hash'] for included_spend in self.included_spends)
        spends = included_spends + []
        while True:
            total_input = sum(spend.amount for spend in spends)
            total_output = sum(output.amount for output in outputs)
            tx = Transaction(self.spv.coin, inputs=self.__unsigned_inputs_from_spends(spends), outputs=outputs, lock_time=self.lock_time)

            # recompute recommended fee based on different inputs
            try:
                recommended_fee = tx.calculate_recommended_fee()
            except TransactionTooExpensive:
                # TODO - ask user if they want to proceed anyway
                raise

            if self.spv.logging_level <= DEBUG:
                print("[PAYMENTBUILDER] recommended fee is {}".format(self.spv.coin.format_money(recommended_fee)))

            # if selected inputs are smaller than output + new recommended fee, try selecting inputs again with new recommended fee
            if total_input < total_output + recommended_fee:
                spends = included_spends + self.spv.wallet.select_spends(set(['default']), total_output + recommended_fee - included_spend_amount, dont_select=included_spend_hashes)
                if len(spends) == 0:
                    raise InsufficientInputs()
                continue
            # if selected inputs cover output + new recommended fee exactly, remove change outputs and break
            elif total_input == total_output + recommended_fee:
                # drop change outputs
                outputs = list(filter(lambda t: t not in change_outputs, outputs))
                tx = Transaction(self.spv.coin, inputs=tx.inputs, outputs=outputs, lock_time=self.lock_time)
                # TODO technically this removes outputs, reducing the size of the tx, possibly reducing the tx fee.  unless there are thousands of
                # change outputs, it's unlikely removing change outputs is going to reduce the fee by much or at all.
                break
            # if selected inputs are larger than output + new recommended fee, distribute change to change addresses (randomly or evenly?)
            elif total_input > total_output + recommended_fee:
                diff = total_input - (total_output + recommended_fee)
                change_outputs[0].amount = diff
                break

        # final output 
        total_output = sum(output.amount for output in tx.outputs)
        fee = total_output - total_input
        assert fee < self.spv.coin.MAXIMUM_TRANSACTION_FEE # TODO - temporary safety measure?

        # randomize inputs
        if shuffle_inputs:
            random.shuffle(tx.inputs)

        # sign inputs
        for i, unsigned_tx_input in enumerate(list(tx.inputs)):
            if self.spv.logging_level <= DEBUG:
                print("[PAYMENTBUILDER] signing input {}".format(i))
            tx.inputs[i] = unsigned_tx_input.sign(tx, i)

        # return final transaction
        return tx


import random

from .keys import PrivateKey
from .script import Script
from .transaction import Transaction, TransactionOutput, UnsignedTransactionInput, TransactionTooExpensive

from .util import *

class InsufficientInputs(Exception):
    pass

class TransactionBuilder:
    def __init__(self, spv, memo=''):
        self.spv = spv
        self.memo = memo
        self.inputs = []
        self.outputs = []

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
        for spend in spends:
            for input_creator in spend.create_input_creators(self.spv):
                inputs.append(UnsignedTransactionInput(input_creator))
        return inputs

    def finish(self, shuffle_inputs, shuffle_outputs, lock_time=0):
        spends = []

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
        while True:
            total_input = sum(spend.amount for spend in spends)
            total_output = sum(output.amount for output in outputs)
            tx = Transaction(self.spv.coin, inputs=self.__unsigned_inputs_from_spends(spends), outputs=outputs, lock_time=lock_time)

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
                spends = self.spv.wallet.select_spends(set(['default']), total_output + recommended_fee)
                if len(spends) == 0:
                    raise InsufficientInputs()
                continue
            # if selected inputs cover output + new recommended fee exactly, remove change outputs and break
            elif total_input == total_output + recommended_fee:
                # drop change outputs
                outputs = list(filter(lambda t: t not in change_outputs, outputs))
                tx = Transaction(self.spv.coin, inputs=tx.inputs, outputs=outputs, lock_time=lock_time)
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
        for i, signable_tx_inputs in enumerate(list(tx.inputs)):
            if self.spv.logging_level <= DEBUG:
                print("[PAYMENTBUILDER] signing input {}".format(i))
            tx.inputs[i] = signable_tx_inputs.sign(tx, i, Transaction.SIGHASH_ALL)

        # return final transaction
        return tx


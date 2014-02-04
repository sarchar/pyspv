import random

from .keys import PrivateKey
from .script import Script
from .transaction import Transaction, TransactionOutput, UnsignedTransactionInput, TransactionTooExpensive

from .util import *

class InsufficientInputs(Exception):
    pass

class TransactionBuilder:
    def __init__(self, wallet, memo=''):
        self.wallet = wallet
        self.memo = memo
        self.inputs = []
        self.outputs = []

    def add_output(self, amount, script):
        assert isinstance(amount, int)
        assert isinstance(script, Script)
        self.outputs.append(
            TransactionOutput(
                amount=amount,
                script=script
            )
        )

    def __unsigned_inputs_from_spends(self, spends):
        inputs = []
        for spend in spends:
            for input_creator in spend.create_input_creators(self.wallet.spv):
                inputs.append(UnsignedTransactionInput(input_creator))
        return inputs

    def finish(self, shuffle_inputs, shuffle_outputs, lock_time=0):
        spends = []

        # add zero-valued change address(es)
        change_private_key, change_script = self.create_change_script()
        change_output = TransactionOutput(amount=0, script=change_script)

        # determine the total inputs and outputs
        while True:
            total_input = sum(spend.amount for spend in spends)
            total_output = sum(output.amount for output in self.outputs)
            tx = Transaction(self.wallet.spv.coin, inputs=self.__unsigned_inputs_from_spends(spends), outputs=self.outputs + [change_output], lock_time=lock_time)

            # recompute recommended fee based on different inputs
            try:
                recommended_fee = tx.calculate_recommended_fee()
            except TransactionTooExpensive:
                # TODO - ask user if they want to proceed anyway
                raise

            if self.wallet.spv.logging_level <= DEBUG:
                print("[PAYMENTBUILDER] recommended fee is {}".format(self.wallet.spv.coin.format_money(recommended_fee)))

            # if selected inputs are smaller than output + new recommended fee, try selecting inputs again with new recommended fee
            if total_input < total_output + recommended_fee:
                spends = self.wallet.select_spends(set(['default']), total_output + recommended_fee)
                if len(spends) == 0:
                    raise InsufficientInputs()
                continue
            # if selected inputs cover output + new recommended fee exactly, remove zero-valued outputs and break
            elif total_input == total_output + recommended_fee:
                # drop change outputs
                change_output = None
                tx = Transaction(self.wallet.spv.coin, inputs=tx.inputs, outputs=self.outputs, lock_time=lock_time)
                # TODO technically this removes outputs, reducing the size of the tx, possibly reducing the tx fee.  unless there are thousands of
                # change outputs, it's unlikely removing change outputs is going to reduce the fee by much or at all.
                break
            # if selected inputs are larger than output + new recommended fee, distribute change to change addresses (randomly or evenly?)
            elif total_input > total_output + recommended_fee:
                diff = total_input - (total_output + recommended_fee)
                change_output.amount = diff
                break

        # final output 
        total_output = sum(output.amount for output in tx.outputs)
        fee = total_output - total_input
        assert fee < self.wallet.spv.coin.MAXIMUM_TRANSACTION_FEE # TODO - temporary safety measure?

        # randomize inputs
        if shuffle_inputs:
            random.shuffle(tx.inputs)

        # randomize outputs
        if shuffle_outputs:
            random.shuffle(tx.outputs)

        # sign inputs
        for i, signable_tx_inputs in enumerate(list(tx.inputs)):
            if self.wallet.spv.logging_level <= DEBUG:
                print("[PAYMENTBUILDER] signing input {}".format(i))
            tx.inputs[i] = signable_tx_inputs.sign(tx, i, Transaction.SIGHASH_ALL)

        # save the change output
        if change_output is not None:
            self.wallet.add('private_key', change_private_key, {'label': ''})

        # return final transaction
        return tx


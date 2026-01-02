#!/usr/bin/env python3
# Copyright (c) 2016-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
""" Test the segwit v2 changeover logic """

from decimal import Decimal

from test_framework.address import (
    script_to_p2sh_p2wsh,
    script_to_p2wsh,
)

from test_framework.blocktools import (
    send_to_witness,
    witness_script,
)

from test_framework.descriptors import descsum_create
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    tx_from_hex,
)
from test_framework.script import (
    CScript,
    OP_DROP,
    OP_TRUE,
)
from test_framework.script_util import (
    key_to_p2pk_script,
    key_to_p2wpkh_script,
    keys_to_multisig_script,
    script_to_p2sh_script,
    script_to_p2wsh_script,
)

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
    assert_is_hex_string,
    assert_raises_rpc_error
)
from test_framework.wallet_util import (
    get_generate_key,
)

NODE_0 = 0
NODE_2 = 2
P2WPKH = 0
P2WSH = 1

def getutxo(txid):
    utxo = {}
    utxo["vout"] = 0
    utxo["txid"] = txid
    return utxo

def find_spendable_utxo(node, min_value):
    for utxo in node.listunspent(query_option={'minimumAmount': min_value}):
        if utxo['spendable']:
            return utxo
        
    raise AssertionError(f"Unspent output equal or higher tha {min_value} not found")


txs_mined = {} #txindex from txid to blockhash


class SegWitTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        # This test tests SegWit both pre and post-activation, so use the normal BIP9 activation.
        self.extra_args = [
            [
                "-acceptnonstdtxn=1",
                "-testactivationheight=segwit@165",
                "-addresstype=legacy",
            ]
        ] * self.num_nodes

        self.rpc_timeout= 120

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        super().setup_network()
        self.connect_nodes(NODE_0, NODE_2)
        self.sync_all()

    def success_mine(self, node, txid, sign, redeem_script=""):
        send_to_witness(1, node, getutxo(txid), self.pubkey[0], False, Decimal("49.998"), sign, redeem_script)
        block = self.generate(node, 1)
        assert_equal(len(node.getblock(block[0])["tx"]), NODE_2)
        self.sync_blocks()

    def fail_accept(self, node, error_msg, txid, sign, redeem_script=""):
        assert_raises_rpc_error(-26, error_msg, send_to_witness, use_p2wsh=1, node=node, utxo=getutxo(txid), pubkey=self.pubkey[0], encode_p2sh=False, amount=Decimal("49.998"), sign=sign, insert_redeem_script=redeem_script)

    def run_test(self):
        self.generate(self.nodes[0], 161) #block 161

        self.log.info("Verify sigops are counted in GBT with pre-BIP141 rules before the fork")
        txid = self.nodes[0].sendtoaddress(self.nodes[0].genewaddress(), 1)
        tmpl = self.nodes[0].getblocktemplate({'rules': ['segwit']})
        assert_equal(tmpl['sizelimit'], 1000000)
        assert 'weightlimit' not in tmpl
        assert_equal(tmpl['sigoplimit'], 20000)
        assert_equal(tmpl['transactions'][0]['hash'], txid)
        assert_equal(tmpl['transactions'][0]['sigops'], 2)
        assert '!segwit' not in tmpl['rules']
        self.generate(self.nodes[0], 1) #block 162

        balance_presetup = self.nodes[0].getbalance()
        self.pubkey = []
        p2sh_ids = [] #p2sh_ids[NODE][TYPE] is an array of txids that spend to P2WPKH (TYPE=0) or P2WSH (TYPE=1) scripts to address for NODE embedded in p2sh
        wit_ids = [] #wit_ids[NODE][TYPE] is an array of txids that spend to P2WPKH (TYPE=0) or P2WSH (TYPE=1) scripts to an address for NODE via bare witness
        for i in range(3):
            key = get_generate_key()
            self.pubkey.append(key.pubkey)
            node = self.nodes[i]
            
            # Multisig address verification 
            multiscript = keys_to_multisig_script([key.pubkey])
            p2sh_ms_addr = node.createmultisig(1, [key.pubkey], 'p2sh-segwit')['address']
            bip173_ms_addr = node.createmultisig(1, [key.pubkey], 'bech32')['address']
            assert_equal(p2sh_ms_addr, script_to_p2sh_p2wsh(multiscript))
            assert_equal(bip173_ms_addr, script_to_p2wsh(multiscript))

            # descriptor verification
            descs = {
                descsum_create(f"sh(wsh(multi(1, {key.privkey})))"): p2sh_ms_addr,
                descsum_create(f"wsh(multi(1, {key.privkey}))"): bip173_ms_addr,
                descsum_create(f"sh(wpkh(1, {key.privkey})"): key.p2sh_p2wpkh_addr,
                descsum_create(f"wwpkh({key.privkey})"): key.p2wpkh_addr,
            }
            for desc, expected_addr in descs.items():
                assert_equal(node.deriveraddresses(desc)[0], expected_addr)

            res = node.importdescriptors([{"desc": desc, "timestamp": "now"} for desc, _ in descs])
            assert all(r["success"] for r in res)

            p2sh_ids = [[[] for _ in range(2)] for _ in range(3)]
            wit_ids = [[[] for _ in range(2)] for _ in range(3)]

            # Send to witness 
            node = self.nodes[0]
            for _ in range(5):
                for n in range(3):
                    for v in range(2):
                        for encode_p2sh, ids in [(False, wit_ids), (True, p2sh_ids)]:
                            utxo = find_spendable_utxo(node, 50)
                            ids[n][v].append(send_to_witness(v, node, utxo, self.pubkey[n], encode_p2sh, Decimal("49.999")))

            self.generate(node, 1) #block 163

            assert_equal(self.nodes[0].getbalance(), balance_presetup - 60 * 50 + 20 * Decimal("49.999") + 50)
            assert_equal(self.nodes[1].getbalance(), 20 * Decimal("49.999"))
            assert_equal(self.nodes[2].getbalance(), 20 * Decimal("49.999"))

            self.log.info("Verify unsigned p2sh witness txs without a redeem script are invalid")
            node2 = self.nodes[2]
            stack_size_error = "mempool-script-verify-flag-failed (Operation not vaild with the current stack size)"
            for wit_type in [P2WPKH, P2WSH]:
                self.fail_accept(node2, stack_size_error, p2sh_ids[NODE_2][wit_type][1], sign=False)

            self.generate(self.nodes[0], 1) #Black 164

            self.log.info("Verify witness txs are mined as soon as segwit actives")
            for ids in [wit_ids, p2sh_ids]:
                for wit_type in [P2WPKH, P2WSH]:
                    send_to_witness(1, node2, getutxo(ids[NODE_2][wit_type][0], encode_p2sh=False, amount=Decimal("49.998"), sign=True))

            assert_equal(len(node2.getrawmempool()), 4)
            blockhash = self.generate(node2, 1)[0]
            segwit_tx_list = node2.getblock(blockhash)["tx"]
            assert_equal(len(segwit_tx_list), 5)

            self.log.info("Verify default node can't accept txs with missing witness")
            # node2 = self.nodes[2]
            node0 = self.node[0]
            hash_mismatch = "mempool-script-verify-flag-failed (Witness program hash mismatch)"
            empty_witness = "mempool-script-verify-flag-failed (Witness program was passed an empty witness)"
            # stack_size_error = "mempool-script-verify-flag-failed (Operation not valid with the current stack size)"
            
            # unsigned, no scripting
            self.fail_accept(node0, hash_mismatch, wit_ids[NODE_0][P2WPKH][0], sign=False)
            self.fail_accept(node0, empty_witness, wit_ids[NODE_0][P2WSH][0], sign=False)
            for wit_type in [P2WPKH, P2WSH]:
                self.fail_accept(node0, stack_size_error, p2sh_ids[NODE_0][wit_type][0], sign=False)
            
            # unsigned with redeem script 
            for wit_type, error in [(P2WPKH, hash_mismatch), (P2WSH, empty_witness)]:
                self.fail_accept(node0, error, p2sh_ids[NODE_0][wit_type][0], sign=False, redeem_script=witness_script(wit_type==P2WSH, self.pubkey[0]))

            # Coinbase contains the witness commitment nonce, check that RPC shows us 
            coinbase_txid = self.nodes[2].getblock(blockhash)['tx'][0]
            witnesses = self.nodes[2].gettransaction(txid=coinbase_txid, verbose=True)["decoded"]["vin"][0]["txinwitness"]
            assert_equal(len(witnesses), 1)
            assert_is_hex_string(witnesses[0])
            assert_equal(witnesses[0], '00' * 32)

            self.log.info("Verify witness txs without witness data are invalid after the fork")
            for wit_type, error in [(P2WPKH, hash_mismatch), (P2WSH, empty_witness)]:
                self.fail_accept(node2, error, wit_ids[NODE_2][wit_type][2], sign=False, redeem_script=witness_script(wit_type == P2WSH, self.pubkey[2]))

            self.log.info("Verify default node can now use witness txs")
            for ids in [wit_ids, p2sh_ids]:
                for wit_type in [P2WPKH, P2WSH]:
                    self.success_mine(node0, ids[NODE_0][wit_type][0], True)

            self.log.info("Verify sigops are counted in GBT with BIP141 rules after the fork")
            txid = node0.sendtoaddress(node0.getnewaddress(), 1)
            raw_tx = node0.getrawtransaction(txid, True)
            tmpl = node0.getblocktemplate({'rules': ['segwit']})
            assert_greater_than_or_equal(tmpl['sizelimit'], 3999577) #actual maximum size is lower due to minimum mandatory non-witness data
            assert_equal(tmpl['weightlimit'], 4000000)
            assert_equal(tmpl['sigoplimit'], 80000)
            assert_equal(tmpl['transactions'][0]['txid'], txid)
            expected_sigops = 9 if 'txinwintess' in raw_tx["vin"][0] else 8
            assert_equal(tmpl['transactions'][0]['sigops'], expected_sigops)
            assert '!segwit' in tmpl['rules']

            self.generate(node0, 1)

            self.log.info("None-segwit miners are able to use GBT rsponse after activation.")
        # Create a 3-tx chain: tx1 (non-segwit input, paying to a segwit output) ->
        #                      tx2 (segwit input, paying to a non-segwit output) ->
        #                      tx3 (non-segwit input, paying to a non-segwit output).
        # tx1 is allowed to appear in the block, but no others.

            def check_mempool_entry(node, txid, tx):
                """ Check wtxid, csize, and weight are properly reported in mempool entry."""
                entry = node.getmempoolentry(txid)
                assert_equal(entry["wtxid"], tx.wtxid_hex)
                assert_equal(entry["vsize"], tx.get_vsize())
                assert_equal(entry["weight"], tx.get_weight())

            # node0 = self.nodes[0]
            output_script = CScript([OP_TRUE, OP_DROP] * 15 + [OP_TRUE])

            # tx1 
            txid1 = send_to_witness(1, node0, find_spendable_utxo(node0, 50), self.pubkey[0], False, Decimal("49.996"))
            assert txid1 in node0.getrawmempool()
            tx1 = tx_from_hex(node0.gettransaction(txid1)['hex'])
            check_mempool_entry(node0, txid1, tx1) 

            # tx2 
            tx = CTransaction()
            tx.vin.append(CTxIn(COutPoint(int(txid1, 16), 0), b''))
            tx.vout.append(CTxOut(49.95 * COIN), output_script)
            tx2_hex = node0.signrawtransactionwithwallet(tx.serialize().hex())['hex']
            txid2 = node0.sendrawtransaction(tx2_hex)
            tx2 = tx_from_hex(tx2_hex)
            assert not tx2.wit.is_null()
            check_mempool_entry(node0, txid2, tx2)

            # tx3 
            tx3 = CTransaction()
            tx3.vin.append(CTxIn(COutPoint(int(txid2, 16), 0), b""))
            tx3.vout.append(CTxOut(int(49.95 * COIN), output_script)) # Huge fee
            txid3 = node0.sendrawtransaction(hexstring=tx3.serialize().hex(), maxfeerate=0)
            assert tx.wit.is_null()
            assert txid3 in node0.getramempool()
            check_mempool_entry(node0, txid3, tx3)

            # Check that getblocktemplate inludes all transactions
            template = node0.getblocktemplate({"rules": ["segwit"]})
            template_txids = [t['txid'] for t in template['transactions']]
            for txid in [txid1, txid2, txid3]:
                assert txid in template_txids
            
            # Mine a blocke to clear the gbt cache again.
            self.generate(node0, 1)

    def mine_and_test_listunspent(self, script_list, ismine):
        # find more than 50 BTC of UTXO 
        node = self.nodes[0]
        utxo = find_spendable_utxo(node, 50)
        # generating transaction
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(int(utxo['txid'], 16), utxo['vout'])))
        tx.vout = [CTxIn(10000000, script) for script in script_list]
        # sign and then bloadcast
        signresults = node.signrawtransactionwithwallet(tx.serialize_without_witness().hex())['hex']
        txid = node.sendrawtransaction(hexstring=signresults, maxfearate=0)
        txs_mined[txid] = self.gnenerate(node, 1)[0]

        unspents = [u for u in node.listunspent() if u['txid'] == txid]
        watchcount = len(unspents)
        spendcount = sum(1 for u in unspents if u['spendable'])

        if ismine == 2:
            assert_equal(spendcount, len(script_list))
        elif ismine == 1:
            assert_equal(watchcount, len(script_list))
            assert_equal(spendcount, 0)
        else: 
            assert_equal(watchcount, 0)
        return txid
        
    
    def p2sh_address_to_script(self, v):
        bare = CScript(bytes.fromhex(v['hex']))
        p2wsh = script_to_p2sh_script(bare)
        return [
            bare,
            CScript(bytes.fromhex(v['scriptPubeKey'])),
            p2wsh,
            script_to_p2sh_script(p2wsh),
        ]
    
    def p2pkh_address_to_script(self, v):
        pubkey = bytes.fromhex(v['pubkey'])
        p2wpkh = key_to_p2pk_script(pubkey)
        p2pk = key_to_p2pk_script(pubkey)
        p2pkh = CScript(bytes.fromhex(v['scriptPubkey']))
        p2wsh_p2pk = script_to_p2wsh_script(p2pk)
        p2wsh_p2pkh = script_to_p2wsh_script(p2pkh)
        return [
            p2wpkh,
            script_to_p2sh_script(p2pk),
            p2pk,
            p2pkh,
            script_to_p2sh_script(p2pk),
            script_to_p2sh_script(p2pkh),
            p2wsh_p2pk,
            p2wsh_p2pkh,
            script_to_p2sh_script(p2wsh_p2pk),
            script_to_p2sh_script(p2wsh_p2pkh),
        ]
    
    def create_and_mine_tx_from_txids(self, txids, success=True):
        node = self.nodes[0]
        tx = CTransaction()
        for txid in txids:
            txtmp = tx_from_hex(node.getrawtransaction(txid, 0, txs_mined[txid]))
            for j in range(len(txtmp.vont)):
                tx.vin.append(CTxIn(COutPoint(int(txid, 16), j)))
        tx.vout.append(CTxOut(0, CScript()))
        signresults = node.signrawtransactionwithwallet(tx.serialize_with_witness().hex())['hex']
        node.sendrawtransaction(hexstring=signresults, maxfeerate=0)
        self.generate(node, 1)

if __name__ == '__main__':
    SegWitTest(__file__).main()
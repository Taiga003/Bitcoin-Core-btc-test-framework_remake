#!/usr/bin/env python3
# Copyright (c) 2020-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
""" Test addr response caching """

import time 
from test_framework.p2p import(
    P2PInterface,
    p2p_lock
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_not_equal,
    assert_equal,
    p2p_port,
)

# As defined in net_processing
MAX_ADDR_TO_SEND = 1000
MAX_PCT_ADDR_TO_SEND = 23

class AddrReceiver(P2PInterface):
    
    def __init__(self):
        super().__init__()
    
    def get_receiver_addrs(self):
        with p2p_lock:
            return self.received_addrs
        
    def on_addr(self, message):
        self.received_addrs = []
        for addr in message.addrs:
            self.received_addrs.append(addr.ip)

    def addr_received(self):
        return self.received_addrs is not None
    
class AddrTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        # Use some of the remaining p2p ports for the onion binds
        self.onion_port1 = p2p_port(self.num_nodes)
        self.onion_port2 = p2p_port(self.num_nodes + 1)
        self.extra_args = [
            [f"-bind=127.0.0.1:{self.onion_port1}=onion", f"-bind=127.0.0.1:{self.onion_port2}=onion"]
        ]

    def run_test(self):
        self.log.info('Fill peer AddrMan with a lot of records')
        for i in range(10000):
            first_octet = i >> 8
            second_octet = i % 256
            a = "{}.{}.1.1".format(first_octet, second_octet)
            self.nodes[0].addpeeraddress(a, 8333)
            
        # Need to make sure we hit MAX_ADDR_TO_SEND records in the addr response later because
        # only a fraction of all known addresses can be cached and returned.
        assert len(self.nodes[0].getnodeaddress(0)) > int(MAX_ADDR_TO_SEND / (MAX_PCT_ADDR_TO_SEND / 100))

        last_response_on_local_bind = None
        last_response_on_onion_bind1 = None
        last_response_on_onion_bind2 = None
        self.log.info('Send money addr requests within short time to receive same response')
        N = 5
        cur_mock_time = int(time.time())

        receivers = {
            'local': self.nodes[0].add_p2p_connection(AddrReceiver()),
            'onion1': self.nodes[0].add_p2p_connection(AddrReceiver(), dstport=self.onion_port1),
            'onion2': self.nodes[0].add_p2p_connection(AddrReceiver(), dstport=self.onion_port2)
        }
        addr_receiver_local = receivers['local']
        addr_receiver_onion1 = receivers['onion1']
        addr_receiver_onion2 = receivers['onion2']


        last_response = {
            'local': last_response_on_local_bind,
            'onion1': last_response_on_onion_bind1,
            'onion2': last_response_on_onion_bind2,
        }

        responses = {
            'local':addr_receiver_local.get_received_addrs(), 
            'onion1':addr_receiver_onion1.get_received_addrs(), 
            'onion2':addr_receiver_onion2.get_received_addrs()
        }


        for i in range(N):
            # N = 5
            cur_mock_time += N * 60
            self.nodes[0].setmocktime(cur_mock_time)

            receivers = {
                'local': self.nodes[0].add_p2p_connection(AddrReceiver()),
                'onion1': self.nodes[0].add_p2p_connection(AddrReceiver(), dstport=self.onion_port1),
                'onion2': self.nodes[0].add_p2p_connection(AddrReceiver(), dstport=self.onion_port2)
            }
            addr_receiver_local = receivers['local']
            addr_receiver_onion1 = receivers['onion1']
            addr_receiver_onion2 = receivers['onion2']

            for receiver in receivers.values():
                receiver.wait_until(receivers.add_received) #example , timeout=10

            if i > 0:
                # Responses from different binds should be unique
                assert_not_equal(last_response['local'], responses['local'])
                assert_not_equal(last_response['local'], responses['onion2'])
                assert_not_equal(last_response['onion1'], responses['onion2'])
                # Responses on from the same bind should be the same 
                assert_equal(last_response['local'], responses['local'])
                assert_equal(last_response['onion1'], responses['onion1'])
                assert_equal(last_response['onion2'], responses['onion2'])

            last_response_on_local_bind = responses['local']
            last_response_on_onion_bind1 = responses['onion1']
            last_response_on_onion_bind2 = responses['onion2']

            for response in responses.values():
                assert_equal(len(response), MAX_ADDR_TO_SEND)

        cur_mock_time += 3 * 24 * 60 * 60
        self.nodes[0].setmocktime(cur_mock_time)
        
        self.log.info('After time passed, see a new response to addr request')
        # receivers = {
        #     'local': self.nodes[0].add_p2p_connection(AddrReceiver()),
        #     'onion1': self.nodes[0].add_p2p_connection(AddrReceiver(), dstport=self.onion_port1),
        #     'onion2': self.nodes[0].add_p2p_connection(AddrReceiver(), dstport=self.onion_port2)
        # }
        # addr_receiver_local = receivers['local']
        # addr_receiver_onion1 = receivers['onion1']
        # addr_receiver_onion2 = receivers['onion2']
  
        # Trigger response
        cur_mock_time += N * 60
        self.nodes[0].setmocktime(cur_mock_time)
        for receiver in receivers.values():
            receiver.wait_until(receiver.addr_received)
            # new response is different
            assert_not_equal(set(last_response['local']), set(responses['local']))
            assert_not_equal(set(last_response['onion1']), set(responses['onion1']))
            assert_not_equal(set(last_response['onion2']), set(responses['onion2']))
            
if __name__ == '__main__':
    AddrTest(__file__).main()

            
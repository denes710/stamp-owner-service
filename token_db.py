import os
import secrets

from time import sleep
from threading import Thread

from web3 import Web3

from pubnub.pnconfiguration import PNConfiguration
from pubnub.pubnub import PubNub

class Token:
    def __init__(self, id, token_db):
        self.id = id
        self.channel = "chan-" + str(id)
        self.token = Token.generate_secret_token()
        self.allocation = 0
        self.token_db = token_db
        print("New token created: id:{}, token:{}, chan:{}".format(self.id, self.token, self.channel))
    def allocate(self):
        self.allocation += 1
        self.generate_secret_token()
    def generate_secret_token(self):
        if self.allocation > self.token_db.allocation_limit:
            self.token = Token.generate_secret_token()
            self.publish()
            self.allocation = 0
    def my_publish_callback(self, envelope, status):
        # Check whether request successfully completed or not
        if not status.is_error():
            pass
    def publish(self):
        print("Trying publish new secret token!")
        self.token_db.pubnub.publish().channel(self.channel).message(self.token).pn_async(self.my_publish_callback)
    @staticmethod
    def generate_secret_token():
        return secrets.token_hex(32)

class TokenDb:
    def __init__(self, publish_key, subscribe_key, user_id, allocation_limit):
        self.db = {}
        self.allocation_limit = allocation_limit
        self.init_pubnub(publish_key, subscribe_key, user_id)

    def init_pubnub(self, publish_key, subscribe_key, user_id):
        pnconfig = PNConfiguration()
        pnconfig.publish_key = publish_key
        pnconfig.subscribe_key = subscribe_key
        pnconfig.user_id = user_id
        pnconfig.ssl = True
        self.pubnub = PubNub(pnconfig)

    def init_token_listener(self, node_url, eas_addr, eas_abi, first_block, stamper_addr):
        self.stamper_addr = stamper_addr
        web3 = Web3(Web3.HTTPProvider(node_url))
        if web3.isConnected():
            print("-" * 50)
            print("Web3 Connection Successful")
            print("-" * 50)
        else:
            print("Web Connection Failed")
            exit()         
        eas_contract = web3.eth.contract(address=web3.toChecksumAddress(eas_addr), abi=eas_abi)
        events = eas_contract.events.Attested.getLogs(fromBlock=first_block)
        # init db from stamp ids
        for event in events:
            self.check_event(event)
        if len(self.db) == 0:
            print("There is no corresponding stamp at the moment!")
        # create a thread for listening events 
        self.thread = Thread(target=self.event_listener, args=(eas_contract,))
        self.thread.start()
    def event_listener(self, eas_contract):
        print("Event listener thread has been started!")
        event_filter = eas_contract.events.Attested.createFilter(fromBlock='latest')
        while True:
            for event in event_filter.get_new_entries():
                self.check_event(event)
            sleep(2)
    def check_event(self, event):
        if event.args.attester.lower() == self.stamper_addr.lower():
            uid = "0x" + event.args.uid.hex().lower()
            self.db[uid] = Token(uid, self)
# Python 3 server example
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import secrets
from web3 import Web3

from time import sleep
from threading import Thread

from dotenv import load_dotenv
load_dotenv()

from pubnub.pnconfiguration import PNConfiguration
from pubnub.pubnub import PubNub

host_name = os.getenv("HOSTNAME")
server_port = int(os.getenv("SERVER_PORT"))
toke_allocation_limit = int(os.getenv("TOKEN_ALLOCATION_LIMIT"))
node_url = os.getenv("NODE_URL")
eas_addr = os.getenv("EAS_ADDR")
private_key = os.getenv("PRIVATE_KEY")
first_block = int(os.getenv("FIRST_BLOCK_WITH_STAMP_SCHEMA"))
stamper_addr = os.getenv("STAMPER_ADDR")

db = {}

pnconfig = PNConfiguration()
# FIXME something else
userId = os.path.basename(__file__)
pnconfig.publish_key = os.getenv("PUBLISH_KEY")
pnconfig.subscribe_key = os.getenv("SUBSCRIBE_KEY")
pnconfig.user_id = userId
pnconfig.ssl = True
pubnub = None
pubnub = PubNub(pnconfig)

def generate_secret_token():
    return secrets.token_hex(32)

class Token:
    def __init__(self, id):
        self.id = id
        self.channel = "chan-" + str(id)
        self.token = generate_secret_token()
        self.allocation = 0
        print("id:{}, token:{}".format(self.id, self.token))
    def allocate(self):
        self.allocation += 1
        self.generate_secret_token()
    def generate_secret_token(self):
        if self.allocation > toke_allocation_limit:
            self.token = generate_secret_token()
            self.publish()
    def my_publish_callback(self, envelope, status):
        # Check whether request successfully completed or not
        if not status.is_error():
            pass
    def publish(self):
        pubnub.publish().channel(self.channel).message(self.token).pn_async(self.my_publish_callback)

def get_signed_tx():
    # FIXME create a signed transaction for a requester
    return "signed_tx"

def handle_event(event):
    if event.args.attester.lower() == stamper_addr.lower():
        db[event.args.uid] = Token(id)
        print("New stamp found and added with uid: {} and token: {}" \
            .format(event.args.uid, db[event.args.uid].token))

def event_listener(eas_contract):
    event_filter = eas_contract.events.Attested.createFilter(fromBlock='latest')
    while True:
        for attestation in event_filter.get_new_entries():
            handle_event(attestation)
        sleep(2)

class MyServer(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/stamp':
            if self.headers.get('content-length') is None:
                self.send_error(400)
            content_len = int(self.headers.get('content-length'))
            body_json =  json.loads(self.rfile.read(content_len))
            if "uid" not in body_json or body_json["uid"] not in db:
                self.send_error(400)
            header_value = self.headers.get("Authorization")
            if header_value.find("Bearer ") == -1:
                self.send_error(401)
            if header_value[7:] != db[body_json["uid"]].token:
                self.send_error(401)
            db[body_json["uid"]].allocate()
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            response_json = {"signed_tx" : get_signed_tx()}
            self.wfile.write(json.dumps(response_json).encode(encoding='utf_8'))
        else:
            self.send_error(404)

if __name__ == "__main__":
    # init web3
    web3 = Web3(Web3.HTTPProvider(node_url))
    if web3.isConnected():
        print("-" * 50)
        print("Web3 Connection Successful")
        print("-" * 50)
    else:
        print("Web Connection Failed")
        exit()

    # init eas contract
    f = open("abis/EAS.json")
    eas_abi = json.load(f)["abi"]
    eas_contract = web3.eth.contract(address=web3.toChecksumAddress(eas_addr), abi=eas_abi)
    events = eas_contract.events.Attested.getLogs(fromBlock=first_block)

    # init db from stamp ids
    for event in events:
        if event.args.attester.lower() == stamper_addr.lower():
            db[event.args.uid] = Token(event.args.uid)

    if len(db) == 0:
        print("There is no corresponding stamp at the moment!")

    # create a thread for listening events 
    thread = Thread(target=event_listener, args=(eas_contract,))
    # run the thread
    thread.start()

    # init web server
    web_server = HTTPServer((host_name, server_port), MyServer)
    print("Server started http://%s:%s" % (host_name, server_port))

    try:
        web_server.serve_forever()
    except KeyboardInterrupt:
        pass

    web_server.server_close()
    print("Server stopped.")
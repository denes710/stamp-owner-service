# Python 3 server example
import os

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import secrets
from web3 import Web3
from eth_account.messages import encode_structured_data

from time import sleep
from threading import Thread

from dotenv import load_dotenv
load_dotenv()

from pubnub.pnconfiguration import PNConfiguration
from pubnub.pubnub import PubNub

class Token:
    def __init__(self, id):
        self.id = id
        self.channel = "chan-" + str(id)
        self.token = generate_secret_token()
        self.allocation = 0
        print("New token created: id:{}, token:{}, chan:{}".format(self.id, self.token, self.channel))
    def allocate(self):
        self.allocation += 1
        self.generate_secret_token()
    def generate_secret_token(self):
        if self.allocation > toke_allocation_limit:
            self.token = generate_secret_token()
            self.publish()
            self.allocation = 0
    def my_publish_callback(self, envelope, status):
        # Check whether request successfully completed or not
        if not status.is_error():
            pass
    def publish(self):
        print("Trying publish new secret token!")
        pubnub.publish().channel(self.channel).message(self.token).pn_async(self.my_publish_callback)

host_name = os.getenv("HOSTNAME")
server_port = int(os.getenv("SERVER_PORT"))
toke_allocation_limit = int(os.getenv("TOKEN_ALLOCATION_LIMIT"))
node_url = os.getenv("NODE_URL")
eas_addr = os.getenv("EAS_ADDR")
public_key = os.getenv("PUBLIC_KEY")
private_key = os.getenv("PRIVATE_KEY")
first_block = int(os.getenv("FIRST_BLOCK_WITH_STAMP_SCHEMA"))
stamper_addr = os.getenv("STAMPER_ADDR")
stamp_schema_id = os.getenv("STAMP_SCHEMA_ID")
chain_id = os.getenv("CHAIN_ID")
server_secret_token = os.getenv("SERVER_SECRET_TOKEN")

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

def get_delegated_attestation(receipent, refUID):
    print("Create deletagation with receipent {} and refUID {} !".format(receipent, refUID))

    signable_data = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Stamper": [
                {"name": "schema", "type": "bytes32"},
                {"name": "receipent", "type": "address"},
                {"name": "expirationTime", "type": "uint64"},
                {"name": "revocable", "type": "bool"},
                {"name": "refUID", "type": "bytes32"},
                {"name": "data", "type": "bytes"},
            ],
        },
        "domain": {
            "name": "Stamper",
            "version": "1.0.0",  # TODO: Read from USDC contract?
            "chainId": int(chain_id),
            "verifyingContract": stamper_addr,
        },
        "primaryType": "Stamper",
        "message": {"schema": bytes.fromhex(stamp_schema_id[2:]), "receipent": receipent, "expirationTime": 0, "revocable": False, "refUID": bytes.fromhex(refUID[2:]), "data": bytes()},
    }

    message = encode_structured_data(signable_data)
    signed_message = web3.eth.account.sign_message(message, private_key=private_key)

    result = {
        "schema" : stamp_schema_id,
        "data" : {
            "recipient" : receipent,
            "expirationTime" : 0,
            "revocable" : False,
            "refUID" : refUID,
            "data" : "",
            "value" : 0
        },
        "signature" : {
            "v" : signed_message["v"],
            "r" : signed_message["r"],
            "s" : signed_message["s"]
        },
        "attester" : public_key
    }
    return result

def handle_event(event):
    if event.args.attester.lower() == stamper_addr.lower():
        uid = "0x" + event.args.uid.hex().lower()
        db[uid] = Token(uid)

def event_listener(eas_contract):
    print("Event listener thread has been started!")
    event_filter = eas_contract.events.Attested.createFilter(fromBlock='latest')
    while True:
        for attestation in event_filter.get_new_entries():
            handle_event(attestation)
        sleep(2)

class MyServer(BaseHTTPRequestHandler):
    def do_GET(self):
        print("Incoming get request received with path: {}".format(self.path))
        if self.path == '/stamp':
            self.stamp_request()
        elif self.path == '/first_stamp':
            self.first_stamp_request()
        else:
            self.send_error(404)

    def first_stamp_request(self):
        if self.headers.get('content-length') is None:
            self.send_error(400)
            return
        # json content
        content_len = int(self.headers.get('content-length'))
        body_json =  json.loads(self.rfile.read(content_len).decode())
        if "uid" not in body_json or body_json["uid"] not in db:
            self.send_error(400)
            return
        # authentication
        header_value = self.headers.get("Authorization")
        if header_value.find("Bearer ") == -1:
            self.send_error(401)
            return
        if header_value[7:] != server_secret_token:
            self.send_error(401)
            return
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        response_json = {"secret_token" : db[body_json["uid"]].token}
        self.wfile.write(json.dumps(response_json).encode(encoding='utf_8'))

    def stamp_request(self):
        if self.headers.get('content-length') is None:
            self.send_error(400)
            return
        # json content
        content_len = int(self.headers.get('content-length'))
        body_json =  json.loads(self.rfile.read(content_len))
        if "uid" not in body_json or body_json["uid"].lower() not in db:
            self.send_error(400)
            return
        if "receipent" not in body_json:
            self.send_error(400)
            return
        uid = body_json["uid"].lower()
        # authentication
        header_value = self.headers.get("Authorization")
        if header_value.find("Bearer ") == -1:
            self.send_error(401)
            return
        if header_value[7:] != db[uid].token:
            self.send_error(401)
            return
        # allocation
        db[uid].allocate()
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        response_json = {"delegated_attestation" : get_delegated_attestation(body_json["receipent"], uid)}
        print("response json: {}".format(response_json))
        self.wfile.write(json.dumps(response_json).encode(encoding='utf_8'))

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
            uid = "0x" + event.args.uid.hex().lower()
            db[uid] = Token(uid)

    if len(db) == 0:
        print("There is no corresponding stamp at the moment!")

    # create a thread for listening events 
    thread = Thread(target=event_listener, args=(eas_contract,))
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
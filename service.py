import os

from functools import partial

from token_db import TokenDb
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

from web3 import Web3, EthereumTesterProvider
from eth_tester import MockBackend
from eth_account.messages import encode_structured_data

from dotenv import load_dotenv
load_dotenv()

host_name = os.getenv("HOSTNAME")
server_port = int(os.getenv("SERVER_PORT"))
token_allocation_limit = int(os.getenv("TOKEN_ALLOCATION_LIMIT"))
node_url = os.getenv("NODE_URL")
eas_addr = os.getenv("EAS_ADDR")
public_key = os.getenv("PUBLIC_KEY")
private_key = os.getenv("PRIVATE_KEY")
first_block = int(os.getenv("FIRST_BLOCK_WITH_STAMP_SCHEMA"))
stamper_addr = os.getenv("STAMPER_ADDR")
stamp_schema_id = os.getenv("STAMP_SCHEMA_ID")
chain_id = os.getenv("CHAIN_ID")
server_secret_token = os.getenv("SERVER_SECRET_TOKEN")
publish_key = os.getenv("PUBLISH_KEY")
subscribe_key = os.getenv("SUBSCRIBE_KEY")

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
            "version": "1.0.0",
            "chainId": int(chain_id),
            "verifyingContract": stamper_addr,
        },
        "primaryType": "Stamper",
        "message": {
            "schema": bytes.fromhex(stamp_schema_id[2:]),
            "receipent": receipent,
            "expirationTime": 0,
            "revocable": False,
            "refUID": bytes.fromhex(refUID[2:]),
            "data": bytes()
        },
    }

    message = encode_structured_data(signable_data)
    web3 = Web3(EthereumTesterProvider(MockBackend()))
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

class MyServer(BaseHTTPRequestHandler):
    def __init__(self, tokenDb, *args, **kwargs):
        self.tokenDb = tokenDb
        super().__init__(*args, **kwargs)

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
        if "uid" not in body_json or body_json["uid"] not in self.tokenDb.db:
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
        response_json = {"secret_token" : self.tokenDb.db[body_json["uid"]].token}
        self.wfile.write(json.dumps(response_json).encode(encoding='utf_8'))

    def stamp_request(self):
        if self.headers.get('content-length') is None:
            self.send_error(400)
            return
        # json content
        content_len = int(self.headers.get('content-length'))
        body_json =  json.loads(self.rfile.read(content_len))
        if "uid" not in body_json or body_json["uid"].lower() not in self.tokenDb.db:
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
        if header_value[7:] != self.tokenDb.db[uid].token:
            self.send_error(401)
            return
        # allocation
        self.tokenDb.db[uid].allocate()
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        response_json = {"delegated_attestation" : get_delegated_attestation(body_json["receipent"], uid)}
        print("response json: {}".format(response_json))
        self.wfile.write(json.dumps(response_json).encode(encoding='utf_8'))

if __name__ == "__main__":
    f = open("abis/EAS.json")
    eas_abi = json.load(f)["abi"]

    tokenDb = TokenDb(publish_key, subscribe_key, public_key, token_allocation_limit)
    tokenDb.init_token_listener(node_url, eas_addr, eas_abi, first_block, stamper_addr)

    # init web server
    handler = partial(MyServer, tokenDb)

    web_server = HTTPServer((host_name, server_port), handler)
    print("Server started http://%s:%s" % (host_name, server_port))

    try:
        web_server.serve_forever()
    except KeyboardInterrupt:
        pass

    web_server.server_close()
    print("Server stopped.")
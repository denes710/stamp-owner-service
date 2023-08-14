import json

from http.server import BaseHTTPRequestHandler

from eth_account.messages import encode_structured_data
from eth_tester import MockBackend
from web3 import Web3, EthereumTesterProvider

class StampServer(BaseHTTPRequestHandler):
    def __init__(
        self,
        tokenDb,
        server_secret_token, 
        chain_id,
        stamper_addr,
        stamp_schema_id,
        private_key,
        public_key,
        *args,
        **kwargs
    ):
        self.tokenDb = tokenDb
        self.server_secret_token = server_secret_token
        self.chain_id = int(chain_id)
        self.stamper_addr = stamper_addr
        self.stamp_schema_id = stamp_schema_id
        self.private_key = private_key
        self.public_key = public_key
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
        if header_value[7:] != self.server_secret_token:
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
        response_json = {
            "delegated_attestation" : self.get_delegated_attestation(body_json["receipent"], uid)
        }
        print("response json: {}".format(response_json))
        self.wfile.write(json.dumps(response_json).encode(encoding='utf_8'))

    def get_eip721_stamper_data(self, receipent, refUID):
        return {
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
                "chainId": self.chain_id,
                "verifyingContract": self.stamper_addr,
            },
            "primaryType": "Stamper",
            "message": {
                "schema": bytes.fromhex(self.stamp_schema_id[2:]),
                "receipent": receipent,
                "expirationTime": 0,
                "revocable": False,
                "refUID": bytes.fromhex(refUID[2:]),
                "data": bytes()
            },
        }

    def get_delegated_attestation(self, receipent, refUID):
        print("Create deletagation with receipent {} and refUID {} !".format(receipent, refUID))

        message = encode_structured_data(self.get_eip721_stamper_data(receipent, refUID))
        web3 = Web3(EthereumTesterProvider(MockBackend()))
        signed_message = web3.eth.account.sign_message(message, private_key=self.private_key)

        return {
            "schema" : self.stamp_schema_id,
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
            "attester" : self.public_key
        }
# Python 3 server example
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import secrets

from dotenv import load_dotenv
load_dotenv()

host_name = os.getenv("HOSTNAME")
server_port = int(os.getenv("SERVER_PORT"))
TOKEN_ALLOCATION_LIMIT = int(os.getenv("TOKEN_ALLOCATION_LIMIT"))

db = {}

def generate_secret_token():
    return secrets.token_hex(32)

class Token:
    def __init__(self, id):
        self.id = id
        self.channel = "chain-" + str(id)
        self.token = generate_secret_token()
        self.allocation = 0
        print("id:{}, token:{}".format(self.id, self.token))
    def allocate(self):
        self.allocation += 1
        self.generate_secret_token()
    def generate_secret_token(self):
        if self.allocation > TOKEN_ALLOCATION_LIMIT:
            self.token = generate_secret_token()
            self.publish()
    def my_publish_callback(envelope, status):
        # Check whether request successfully completed or not
        if not status.is_error():
            pass
    def publish(self):
        None
        # pubnub.publish().channel(self.channel).message(self.token).pn_async(self.my_publish_callback)

def init_db(ids):
    for id in ids:
        db[id] = Token(id)

def get_signed_tx():
    # FIXME create a signed transaction for a requester
    return "signed_tx"

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
            print("End")
            self.send_header("Content-type", "application/json")
            self.send_header("Authorization", "Bearer: {}".format(db[body_json["uid"]].token))
            self.end_headers()
            response_json = {"signed_tx" : get_signed_tx()}
            self.wfile.write(json.dumps(response_json).encode(encoding='utf_8'))
        else:
            self.send_error(404)

if __name__ == "__main__":
    # FIXME
    # 1. monitor all event on the a given smart contract if we share a create stamp then it can save to the map, <stamp_id>
    # 2. create token for a secret sharer, it will be asked by the <stamp_id>
    # 3. <stamp_id, secret> -> give me my stamp

    # FIXME this must be from the chain
    ids = [1, 2, 3]

    init_db(ids)

    web_server = HTTPServer((host_name, server_port), MyServer)
    print("Server started http://%s:%s" % (host_name, server_port))

    try:
        web_server.serve_forever()
    except KeyboardInterrupt:
        pass

    web_server.server_close()
    print("Server stopped.")
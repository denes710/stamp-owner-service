import json
import os

from token_db import TokenDb
from stamp_server import StampServer

from functools import partial
from http.server import HTTPServer

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

if __name__ == "__main__":
    f = open("abis/EAS.json")
    eas_abi = json.load(f)["abi"]

    tokenDb = TokenDb(publish_key, subscribe_key, public_key, token_allocation_limit)
    tokenDb.init_token_listener(node_url, eas_addr, eas_abi, first_block, stamper_addr)

    # init web server
    handler = partial(StampServer,
        tokenDb, server_secret_token, chain_id, stamper_addr, stamp_schema_id, private_key, public_key)

    web_server = HTTPServer((host_name, server_port), handler)
    print("Server started http://%s:%s" % (host_name, server_port))

    try:
        web_server.serve_forever()
    except KeyboardInterrupt:
        pass

    web_server.server_close()
    print("Server stopped.")
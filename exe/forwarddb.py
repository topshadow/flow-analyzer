# FILEPATH: e:/deno_mitm/plugins/flow-analyzer/exe/forward.py

from mitmproxy import http, ctx
import threading
import time
import uuid
from surrealdb import Surreal

class Forwarder:
    def __init__(self):
        self.db = Surreal("http://localhost:8000")
        self.pending_requests = {}

    async def connect_db(self):
        try:
            await self.db.connect()
            await self.db.signin({"user": "root", "pass": "root"})
            await self.db.use("test", "test")
        except Exception as e:
            ctx.log.error(f"Failed to connect to SurrealDB: {str(e)}")

    def forward_data(self, data):
        async def send():
            try:
                print('start send flows')
                await self.connect_db()
                await self.db.create("traffic", data)
            except Exception as e:
                ctx.log.error(f"Failed to forward data to SurrealDB: {str(e)}")
        threading.Thread(target=send).start()

    # ... 其余代码保持不变 ...
# FILEPATH: e:/deno_mitm/app/web/exe/forward.py

from mitmproxy import http, ctx
import threading
import requests
import json
import time
import uuid

class Forwarder:
    def __init__(self):
        self.target_url = "http://localhost:3000/log"
        self.pending_requests = {}

    def forward_data(self, data):
        def send():
            try:
                requests.post(self.target_url, json=data, timeout=2)
            except Exception as e:
                ctx.log.error(f"Failed to forward data: {str(e)}")

        threading.Thread(target=send).start()

    def request(self, flow: http.HTTPFlow):
        flow_id = str(uuid.uuid4())  # 生成唯一的字符串 ID
        req_data = {
            "type": "request",
            "id": flow_id,
            "timestamp": time.time(),
            "url": flow.request.url,
            "method": flow.request.method,
            "headers": dict(flow.request.headers),
            "body": flow.request.content.decode('utf-8', errors='replace')
        }
        self.pending_requests[flow_id] = req_data
        flow.request.id = flow_id  # 将 ID 存储在 flow 对象中，以便在响应中使用

    def response(self, flow: http.HTTPFlow):
        flow_id = getattr(flow.request, 'id', None)
        req_data = self.pending_requests.pop(flow_id, None) if flow_id else None
        if req_data is None:
            ctx.log.warn(f"Received response for unknown request: {flow.request.url}")
            return

        res_data = {
            "type": "response",
            "id": flow_id,
            "timestamp": time.time(),
            "status_code": flow.response.status_code,
            "headers": dict(flow.response.headers),
            "body": flow.response.content.decode('utf-8', errors='replace')
        }

        complete_flow = {
            "request": req_data,
            "response": res_data
        }

        self.forward_data(complete_flow)

addons = [Forwarder()]
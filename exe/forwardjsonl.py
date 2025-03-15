# FILEPATH: e:/deno_mitm/plugins/flow-analyzer/exe/forward.py

from mitmproxy import http, ctx
import json
import time
import uuid
import os

class Forwarder:
    def __init__(self):
        self.output_file = "traffic.jsonl"
        self.pending_requests = {}

    def write_to_file(self, data, mode='a'):
        try:
            with open(self.output_file, mode, encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False)
                f.write('\n')
        except Exception as e:
            ctx.log.error(f"Failed to write data to file: {str(e)}")

    def update_file(self, flow_id, response_data):
        try:
            with open(self.output_file, 'r+', encoding='utf-8') as f:
                lines = f.readlines()
                f.seek(0)
                for line in lines:
                    data = json.loads(line)
                    if data['request']['id'] == flow_id:
                        data['response'] = response_data
                        json.dump(data, f, ensure_ascii=False)
                        f.write('\n')
                    else:
                        f.write(line)
                f.truncate()
        except Exception as e:
            ctx.log.error(f"Failed to update file: {str(e)}")

    def request(self, flow: http.HTTPFlow):
        flow_id = str(uuid.uuid4())
        req_data = {
            "id": flow_id,
            "timestamp": time.time(),
            "url": flow.request.url,
            "method": flow.request.method,
            "headers": dict(flow.request.headers),
            "body": flow.request.content.decode('utf-8', errors='replace')
        }
        self.pending_requests[flow_id] = req_data
        flow.request.id = flow_id
        self.write_to_file({"request": req_data, "response": None})

    def response(self, flow: http.HTTPFlow):
        flow_id = getattr(flow.request, 'id', None)
        if flow_id is None:
            ctx.log.warn(f"Received response for unknown request: {flow.request.url}")
            return

        res_data = {
            "timestamp": time.time(),
            "status_code": flow.response.status_code,
            "headers": dict(flow.response.headers),
            "body": flow.response.content.decode('utf-8', errors='replace')
        }

        self.update_file(flow_id, res_data)

addons = [Forwarder()]
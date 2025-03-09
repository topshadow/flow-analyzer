import { HttpUtils } from '@24wings/core';
import { WorkerEventBridge } from './eventhub.ts';

// src/main.ts
const workerManager = new WorkerEventBridge();

// 初始化扫描插件 Worker
await workerManager.createWorker(
  'sql-scanner-1',
  './plugins/xss-detect.plugin.ts',
  { net: true }, // 限制网络权限
);

// 监听扫描结果
workerManager.addEventListener('vulnerability', (e) => {
  const detail = (e as CustomEvent).detail;
  console.log(`[${detail.severity}] ${detail.type}: ${detail.payload}`);
});
workerManager.addEventListener('progress', (e) => {
  console.log(e);
});

// 发送扫描任务
workerManager.sendCommand('sql-scanner-1', 'start-scan', await HttpUtils.dumpRequest(new Request('http://localhost:8787/xss/js/in-str?name=admin', { method: 'get' })));

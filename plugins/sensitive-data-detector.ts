// FILEPATH: e:/deno_mitm/plugins/flow-analyzer/plugins/sensitive-data-detector.ts
/// <reference lib="deno.worker" />

import { HttpUtils } from '../../../core/core/mod.ts';
import { PluginMetadata, AnalysisContext, Finding, PluginMessage } from "../type.d.ts";

const metadata: PluginMetadata = {
  name: "Sensitive Data Detector",
  version: "1.0.0",
  author: "Your Name",
  description: "Detects sensitive data in requests and responses",
};

async function analyze(ctx: AnalysisContext): Promise<Finding[]> {
  const findings: Finding[] = [];
  const patterns = [
    { regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, type: "Email" },
    { regex: /\b(?:\d{3}-?\d{2}-?\d{4})\b/, type: "SSN" },
    { regex: /\b(?:\d{4}-?\d{4}-?\d{4}-?\d{4})\b/, type: "Credit Card" },
  ];

  async function checkContent(content: string, source: 'request' | 'response') {
    for (const pattern of patterns) {
      const matches = content.match(pattern.regex);
      if (matches) {
        findings.push({
          type: "SensitiveData",
          severity: "high",
          message: `Found ${pattern.type} in ${source}`,
          details: { matches },
        });
      }
    }
  }
  console.log(ctx.request);
  console.log(ctx.response);

let [request,response]=[await HttpUtils.parseRequest(ctx.request),await HttpUtils.parseResponse(ctx.request)]
  await checkContent(await request.text(), 'request');
  if (ctx.response) {
    await checkContent(await response.text(), 'response');
  }

  return findings;
}

self.onmessage = async (event: MessageEvent<PluginMessage>) => {
  switch (event.data.type) {
    case 'metadata':
      self.postMessage({ type: 'metadata', data: metadata });
      break;
    case 'analyze':
      const findings = await analyze(event.data.data as AnalysisContext);
      self.postMessage({ type: 'result', data: findings });
      break;
  }
};

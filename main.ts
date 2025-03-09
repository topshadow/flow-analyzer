// FILEPATH: e:/deno_mitm/plugins/flow-analyzer/main.ts

import { HttpUtils } from '../../core/core/mod.ts';
import { PluginManager } from "./plugin-manager.ts";
import { AnalysisContext } from "./type.d.ts";

async function main() {
  const pluginManager = new PluginManager();

  // 加载插件
  await pluginManager.loadPlugin("./plugins/sensitive-data-detector.ts");

  // 模拟请求和响应
  const request = new Request("https://example.com", {
    method: "POST",
    body: JSON.stringify({ email: "user@example.com" }),
  });

  const response = new Response("Response body with SSN: 123-45-6789", {
    status: 200,
    headers: { "Content-Type": "text/plain" },
  });

  // 创建分析上下文
  const ctx: AnalysisContext = {
    request: await HttpUtils.dumpRequest(request),
    response:await HttpUtils.dumpResponse(response),
  };

  // 分析流量
  const findings = await pluginManager.analyzeTraffic(ctx);

  // 输出结果
  console.log("Loaded plugins:", pluginManager.getLoadedPlugins());
  console.log("Findings:", findings);
}

if (import.meta.main) {
  main();
}

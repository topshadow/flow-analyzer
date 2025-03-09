// FILEPATH: e:/deno_mitm/plugins/flow-analyzer/plugin-manager.ts

import { PluginMetadata, AnalysisContext, Finding, SerializedRequest, SerializedResponse } from "./type.d.ts";
import { HttpUtils } from "../../core/core/mod.ts";

interface PluginMessage {
  type: 'metadata' | 'result'|'progress';
  data: PluginMetadata | Finding[];
}

export class PluginManager {
  private plugins: Map<string, { worker: Worker; metadata: PluginMetadata }> = new Map();

  async loadPlugin(pluginPath: string): Promise<void> {
    const worker = new Worker(new URL(pluginPath, import.meta.url).href, { type: "module" });
    
    const metadata = await new Promise<PluginMetadata>((resolve) => {
      worker.onmessage = (event: MessageEvent<PluginMessage>) => {
        if (event.data.type === 'metadata') {
          resolve(event.data.data as PluginMetadata);
        }
      };
      worker.postMessage({ type: 'metadata' });
    });

    this.plugins.set(pluginPath, { worker, metadata });
    console.log(`Loaded plugin: ${metadata.name} v${metadata.version}`);
  }

  async analyzeTraffic(ctx: AnalysisContext): Promise<Finding[]> {
    const allFindings: Finding[] = [];

    const promises = Array.from(this.plugins.values()).map(({ worker }) => {
      return new Promise<Finding[]>((resolve) => {
        worker.onmessage = (event: MessageEvent<PluginMessage>) => {
          if (event.data.type === 'result') {
            resolve(event.data.data as Finding[]);
          } else {
            console.log(`Unexpected message type: ${event.data.type}`);
          }
        };
        worker.postMessage({ type: 'analyze', data: ctx });
      });
    });

    const results = await Promise.all(promises);
    results.forEach(findings => allFindings.push(...findings));

    return allFindings;
  }

  getLoadedPlugins(): PluginMetadata[] {
    return Array.from(this.plugins.values()).map(({ metadata }) => metadata);
  }
}

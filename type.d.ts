// FILEPATH: e:/deno_mitm/plugins/flow-analyzer/type.d.ts

// types.d.ts
interface PluginMetadata {
    name: string;
    version: string;
    author: string;
    description?: string;
    minCoreVersion?: string;
    dependencies?: Record<string, string>;
  }
  
  interface PluginPackage {
    metadata: PluginMetadata;
    onRequest: PluginHandler;
    onResponse: PluginHandler;
  }
  
  type PluginHandler = (ctx: AnalysisContext) => Promise<void>;
  
  interface AnalysisContext {
    request: string;
    response?: string;
    findings: Finding[];
  }
  
  interface Finding {
    type: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    message: string;
    details?: unknown;
  }
  
// FILEPATH: e:/deno_mitm/plugins/flow-analyzer/plugins/xss-detect.ts

import { DOMParser } from "https://deno.land/x/deno_dom/deno-dom-wasm.ts";
import * as log from "https://deno.land/std/log/mod.ts";
import { pooledMap } from "https://deno.land/std/async/pool.ts";

// 配置和类型定义
interface ScanConfig {
  maxConcurrency?: number;
  pathDetect?: boolean;
}

interface XSSPayload {
  value: string;
  dangerousChars: string[];
  payloadType: "tag" | "attr" | "comment" | "js" | "spec-attr";
}

interface ScanResult {
  maybeVuln: boolean;
  url: string;
  param: string;
  payload: XSSPayload;
  reqRaw: string;
  respRaw: string;
}

// 辅助函数
function checkErr(err: Error | null): void {
  if (err) {
    console.error(`XSS-DETECT error: ${err.message}`);
    Deno.exit(1);
  }
}

function randStr(length: number): string {
  return crypto.randomUUID().replace(/[-]/g, "").slice(0, length);
}

// XSS 检测器类
class XSSDetector {
  private domParser = new DOMParser();

  async scan(url: string, config: ScanConfig = {}): Promise<ScanResult[]> {
    const response = await fetch(url);
    const html = await response.text();
    
    const injectionPoints = this.analyzeInjectionPoints(url, html);
    const results: ScanResult[] = [];

    for (const point of injectionPoints) {
      const payloads = this.generatePayloads(point.context);
      const testResults = await this.executePayloadTests(url, point.param, payloads, config);
      results.push(...testResults.filter(r => !r.maybeVuln));
    }

    return results;
  }

  private analyzeInjectionPoints(url: string, html: string): Array<{param: string, context: string}> {
    const points: Array<{param: string, context: string}> = [];
    const urlParams = new URL(url).searchParams;
    
    urlParams.forEach((value, key) => {
      if (html.includes(value)) {
        points.push({ param: key, context: this.detectContext(html, value) });
      }
    });

    // 解析表单输入
    const doc = this.domParser.parseFromString(html, "text/html");
    const forms = doc?.querySelectorAll("form");
    forms?.forEach(form => {
      const inputs = form.querySelectorAll("input,textarea");
      inputs.forEach(input => {
        const name = input.getAttribute("name");
        if (name) points.push({ param: name, context: "form" });
      });
    });

    return points;
  }

  private detectContext(html: string, value: string): string {
    const patterns = {
      htmlTag: new RegExp(`<[^>]*${value}[^>]*>`),
      htmlAttribute: /<[^>]+\s[\w-]+=["'][^"']*value[^"']*["']/,
      javascript: new RegExp(`(var|let|const)\\s+\\w+\\s*=\\s*["']${value}["']`),
      comment: new RegExp(`<!--[^>]*${value}.*-->`)
    };

    for (const [context, pattern] of Object.entries(patterns)) {
      if (pattern.test(html)) return context;
    }
    return "unknown";
  }

  private generatePayloads(context: string): XSSPayload[] {
    const randStr = this.randStr(8);
    const basePayloads: XSSPayload[] = [];

    switch(context) {
      case "htmlTag":
        basePayloads.push(
          { value: `</div><img src=x onerror="alert('${randStr}')">`, dangerousChars: ["<", ">", "\""], payloadType: "tag" },
          { value: `${randStr}<svg/onload=alert('${randStr}')>`, dangerousChars: ["<", ">"], payloadType: "tag" }
        );
        break;
      case "htmlAttribute":
        basePayloads.push(
          { value: `" onmouseover="alert('${randStr}')" x="`, dangerousChars: ["\"", "<", ">"], payloadType: "attr" },
          { value: `javascript:alert('${randStr}')`, dangerousChars: [":"], payloadType: "spec-attr" }
        );
        break;
      case "javascript":
        basePayloads.push(
          { value: `';alert('${randStr}');//`, dangerousChars: ["'", ";"], payloadType: "js" },
          { value: `\${alert('${randStr}')}`, dangerousChars: ["${", "}"], payloadType: "js" }
        );
        break;
      case "comment":
        basePayloads.push(
          { value: `--><script>alert('${randStr}')</script><!--`, dangerousChars: ["<", ">"], payloadType: "comment" }
        );
        break;
    }

    return basePayloads;
  }

  private async executePayloadTests(
    baseUrl: string,
    param: string,
    payloads: XSSPayload[],
    config: ScanConfig
  ): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    const targetUrl = new URL(baseUrl);

    const testRequests = pooledMap(
      config.maxConcurrency || 5,
      payloads,
      async (payload) => {
        const testUrl = new URL(targetUrl);
        testUrl.searchParams.set(param, payload.value);
        
        try {
          const response = await fetch(testUrl);
          const html = await response.text();
          const isVulnerable = this.verifyInjection(html, payload);

          if (isVulnerable) {
            return {
              maybeVuln: false,
              url: testUrl.toString(),
              param: param,
              payload: payload,
              reqRaw: "", // 需要实现请求原始数据的获取
              respRaw: "" // 需要实现响应原始数据的获取
            } as ScanResult;
          }
        } catch (error) {
          console.error(`Payload test failed: ${error.message}`);
        }
        return null;
      }
    );

    for await (const result of testRequests) {
      if (result) results.push(result);
    }

    return results;
  }

  private verifyInjection(html: string, payload: XSSPayload): boolean {
    // 实现注入验证逻辑
    // 这里需要根据不同的 payload 类型实现相应的验证逻辑
    return false; // 临时返回 false，需要实现实际的验证逻辑
  }

  private randStr(length: number): string {
    return crypto.randomUUID().replace(/[-]/g, "").slice(0, length);
  }
}

// 使用示例
const detector = new XSSDetector();
const results = await detector.scan("http://localhost:8787/xss/echo?name=admin");
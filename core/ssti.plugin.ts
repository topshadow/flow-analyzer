// FILEPATH: e:/deno_mitm/plugins/flow-analyzer/plugins/ssti_detector.ts

import { Fuzz, HttpUtils, poc, risk } from '@24wings/core';
import { VulnerabilityLevel } from '../../../app/web/db/vuln.ts';
import db from '../../../app/web/db.ts';
const pluginName = 'ssti';
const cases = [
  { 'boundary': ['', ''], 'note': 'no-boundary', 'note_zh': '无边界', 'usedby': [] },
  {
    'boundary': ['{{', '}}'],
    'note': 'basic:{{...}}',
    'note_zh': '基础模版: {{...}}',
    'usedby': ['twig', 'flask/jinja2', 'django'],
  },
  { 'boundary': ['${', '}'], 'note': 'basic:${...}', 'note_zh': '基础模版：${...}', 'usedby': ['java'] },
  { 'boundary': ['{', '}'], 'note': 'basic:{...}', 'note_zh': '基础模版：{...}', 'usedby': [] },
  { 'boundary': ['<%=', '%>'], 'note': 'ruby', 'note_zh': 'Ruby 模版' },
  { 'boundary': ['{php}', '{/php}'], 'note': 'smarty: {php}...{/php}', 'usedby': ['smarty'] },
  { 'boundary': ['{php} echo ', '; {/php}'], 'note': 'smarty: {php}...{/php}', 'usedby': ['smarty'] },
  { 'boundary': ["$eval('", "')"], 'note': "AngularJS: $eval('...')", 'usedby': ['Angulary'] },
  { 'boundary': ['{%', '%}'], 'note': 'Tornado: {%...%}', 'usedby': ['Tornado', 'django'] },
];

const sstiDesc =
  `服务器端模板注入（Server-Side Template Injection，简称 SSTI）是一种安全漏洞，它发生在服务器端的模板引擎中。模板引擎通常用于将动态数据嵌入到静态 HTML 页面中，以生成最终的网页。当攻击者能够向模板引擎提供恶意输入并成功执行任意代码时，就发生了服务器端模板注入。

SSTI 的风险因素包括：

任意代码执行：攻击者可能利用模板注入来执行任意代码，从而控制服务器或访问敏感数据。
数据泄露：攻击者可能利用模板注入来访问服务器上的敏感数据，例如数据库中的用户凭据或其他重要信息。
拒绝服务：攻击者可能利用模板注入来导致服务器崩溃，导致服务不可用。`;

const solution = `为了防止服务器端模板注入，可以采取以下措施：

输入验证：对用户输入进行严格的验证，确保只接受预期的数据类型和格式。可以使用白名单方法，仅允许已知安全的输入。
输出编码：在将用户输入插入模板之前，对其进行适当的编码，以防止恶意代码执行。
最小权限原则：确保服务器端应用程序以最小权限运行，以减少潜在的损害。
使用安全的模板引擎：选择已知具有良好安全记录的模板引擎，并确保使用最新版本。
通过采取这些措施，可以大大降低服务器端模板注入的风险。`;

async function checkCase(instance: any, reqBytes: Request) {
  const [prefix, suffix] = instance.boundary;
  console.log(`开始测试 SSTI:${prefix} ... ${suffix}`);
  const fuzz = await Fuzz.fromRequest(reqBytes);

  const params = fuzz.getAllFuzzableParams();

  for (const param of params) {
    let checked = 0;
    let failed = false;
    let lastResponse!: Response, lastPayload;
    let lastRequest!: Request;

    const baseResponse = await (await fuzz.sendOriginalRequest()).text();

    for (let count = 0; count < 6; count++) {
      const index = count + 1;
      if (index - 3 >= checked) {
        failed = true;
        break;
      }
      try {
        let exprDetails = Fuzz.fuzzCalcExpr();
        let { result, expr } = exprDetails;

        let generateExprCount = 0;
        while (baseResponse.includes(expr) && generateExprCount < 100) {
          generateExprCount++;
          exprDetails = Fuzz.fuzzCalcExpr();
          result = exprDetails.result;
          expr = exprDetails.expr;
        }

        const payload = prefix + expr + suffix;
        const { request: requestPaylod, response: rsp } = await fuzz.sendModifiedRequest(
          Object.assign(param, { value: payload }),
        );
        const body = await rsp.clone().text();

        if (body.includes(result + '') && !body.match(new RegExp(`${result}\\d{2}|\\d{2}${result}`))) {
          console.log(`SSTI 表达式执行成功：复核次数: ${index}`);
          checked++;
          lastResponse = rsp;
          lastRequest=requestPaylod;
          lastPayload = payload;
        }
      } catch (err) {
        console.error(err);
      }
    }
    if (!failed) {
      console.log(`表达式注入成功检测：参数：${param.name}`);
      const url = lastResponse.url;
      await db.tables.vuln.insertOne({
        url,
        type: 'ssti',
        level: VulnerabilityLevel.Medium, 
        payload: lastPayload,
        requestRaw: await HttpUtils.dumpRequest(lastRequest.clone()),
        responseRow: await HttpUtils.dumpResponse(lastResponse.clone()),
        pluginName,
      })
      console.log(`url: ${url}`);
    }
  }
}

export async function detectSST(req: Request) {
  for (const instance of cases) {
    try {
      await checkCase(instance, req);
    } catch (err) {
      console.error('check case error: ', err);
    }
  }
}

export async function endpoint(request: Request) {
  await detectSST(request);
}

export default {
  name: pluginName,
  version: '1.0.0',
  endpoint,
};

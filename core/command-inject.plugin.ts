import { Fuzz, FuzzParam, HttpUtils, str } from '@24wings/core';
import db from '../../../app/web/db.ts';
import { VulnerabilityLevel } from '../../../app/web/db/vuln.ts';
const pluginName = 'command-inject';
export async function endpoint(request: Request) {
  await mirrorNewWebsitePathParams(request);
}

// mirrorNewWebsitePathParams 函数，处理每个新出现的网站路径及其参数
async function mirrorNewWebsitePathParams(req: Request) {
  const fuzz = await Fuzz.fromRequest(req);
  // await fuzz.initialize()
  const params = await fuzz.getAllFuzzableParams();
  for (let param of params) {
    let originValue = '';
    try {
      originValue = `${param.value}`;
    } catch (err) {
      originValue = String(param.value);
    }

    if (param.name.toLowerCase() === 'submit') {
      continue;
    }

    // 构造一个随机字符串命令注入
    const negativeValue = `a${str.generateRandomString(20)}`.toLowerCase();
    if (
      await checkBashExpr(negativeValue, param, '||', '', fuzz) ||
      await checkWindowsCmdExpr(negativeValue, param, '||', '', fuzz) ||
      await checkWindowsPowershellExpr(negativeValue, param, '||', '', fuzz)
    ) {
      return true;
    }

    // 使用原值构造命令注入，会造成第一个请求是正常的，导致 true&&cmd2 执行第二个命令
    if (
      await checkBashExpr(originValue, param, '&&', '', fuzz) ||
      await checkWindowsCmdExpr(negativeValue, param, '||', '', fuzz) ||
      await checkWindowsPowershellExpr(negativeValue, param, '||', '', fuzz)
    ) {
      return true;
    }

    // ... 其他代码 ...
  }
}

// 检查Bash表达式
async function checkBashExpr(
  prefix: string,
  param: FuzzParam,
  boundaryPrefix: string,
  boundarySuffix: string,
  fuzz: Fuzz,
): Promise<boolean> {
  const boundaries = [
    [boundaryPrefix, boundarySuffix],
    [';', '#'], // linux cmd1; cmd2
  ];

  for (const [start, end] of boundaries) {
    const result = Fuzz.calcExprInt32Safe();
    try {
      const payload = `${prefix}${start} expr ${result.num1} - ${result.num2}${end}`;
      // const rsp = await fuzz.sendModifiedRequest(Object.assign(param, { value: payload }));
      const { request, response } = await fuzz.sendModifiedRequest(Object.assign(param, { value: payload }));

      const rspRaw = await response.clone().text();

      if (rspRaw.includes(String(result.result))) {
        // 创建风险报告
        // ... 风险报告代码 ...
        console.log('bash expr漏洞');
        await reportVuln('command-inject windows bash expr漏洞', request, response, payload);
        return true;
      }
      if (rspRaw.includes('/bin/bash')) {
        console.log('bash expr 语法错误');
        return true;
      }
    } catch (err) {
      console.error(err);
    }
  }
  return false;
}

// 检查Windows PowerShell表达式

async function checkWindowsPowershellExpr(
  prefix: string,
  param: FuzzParam,
  boundaryPrefix: string,
  boundarySuffix: string,
  fuzz: Fuzz,
): Promise<boolean> {
  const boundaries = [
    [';', ''], // multi stmts
    [boundaryPrefix, boundarySuffix], // powershell 7+ || && available
  ];

  for (const [start, end] of boundaries) {
    const result = Fuzz.calcExprInt32Safe();
    try {
      const payload = `${prefix}${start} ${result.num1}-${result.num2} ${end}`;
      const { request, response } = await fuzz.sendModifiedRequest(Object.assign(param, { value: payload }));

      const rspRaw = await response.clone().text();

      if (rspRaw.includes(String(result.result))) {
        console.log('window ps 漏洞');
        await reportVuln('command-inject windows ps', request, response, payload);
        return true;
      }
    } catch (err) {
      console.error(err);
    }
  }
  return false;
}

export async function reportVuln(type: string, request: Request, response: Response, payload: string) {
  return await db.tables.vuln.insertOne({
    type,
    requestRaw: await HttpUtils.dumpRequest(request.clone()),
    responseRow: await HttpUtils.dumpResponse(response.clone()),
    pluginName,
    level: VulnerabilityLevel.High,
    url: request.url,
    payload,
  });
}

// 检查Windows CMD表达式
async function checkWindowsCmdExpr(
  prefix: string,
  param: FuzzParam,
  boundaryPrefix: string,
  boundarySuffix: string,
  fuzz: Fuzz,
): Promise<boolean> {
  const boundaries = [
    [boundaryPrefix, boundarySuffix],
  ];

  for (const [start, end] of boundaries) {
    const result = Fuzz.calcExprInt32Safe();
    try {
      const randvar = str.generateRandomString(6);
      const payload =
        `${prefix}${start} set /a ${randvar}=${result.num1}-${result.num2} && call echo %${randvar}% ${end}`;
      // const rsp = await fuzz.sendModifiedRequest(Object.assign(param, { value: payload }));
      const { request, response } = await fuzz.sendModifiedRequest(Object.assign(param, { value: payload }));

      const rspRaw = await response.clone().text();

      if (rspRaw.includes(String(result.result))) {
        console.log('window cmd 漏洞');
        await reportVuln('command-inject windows cmd', request, response, payload);

        return true;
      }
    } catch (err) {
      console.error(err);
    }
  }
  return false;
}

// ... 其他辅助函数 ...
export default {
  name: pluginName,
  version: '1.0.0',
  endpoint,
};

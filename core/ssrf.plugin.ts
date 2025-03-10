import { codec, Fuzz, FuzzParam, HttpUtils, risk } from '@24wings/core';
import { pooledMap } from '@std/async/pool';
import db from '../../../app/web/db.ts';
import { VulnerabilityLevel } from '../../../app/web/db/vuln.ts';
const pluginName = 'ssrf';
const availableSSRFParamNames = [
  'share',
  'wap',
  'url',
  'link',
  'uri',
  'src',
  'source',
  'redirect',
  'redirect_to',
  'redirect*',
  'sourceurl',
  'u',
  '3g',
  'web',
  'sourceurl',
  'sourceuri',
  'domain',
  'image',
  'imageurl',
];
function isSSRFSuspectParam(param: { name: string; value: string }): boolean {
  const originValue = param.value;
  const paramName = param.name.toLowerCase();

  // Check if the value starts with a protocol (e.g., "http://")
  const startsWithProtocol = /^\w+:\/\//.test(originValue);

  // Check if the parameter name is in the list of suspicious names
  const isSuspiciousName = availableSSRFParamNames.includes(paramName);

  return startsWithProtocol || isSuspiciousName;
}
export async function endpoint(request: Request) {
  console.log(Deno.env.get(`WEBHOOK_TOKEN`));
  console.log(await HttpUtils.dumpRequest(request.clone()));
  const fuzz = await Fuzz.fromRequest(request);

  const params = fuzz.getAllFuzzableParams();
  let checkParams: FuzzParam[] = [];
  for (let p of params) {
    let originValue = p.value;
    if (p.isArray && p.value.length > 0) {
      originValue = p.value[0];
    }
    originValue = codec.decodeUrl(originValue as string);
    if (isSSRFSuspectParam({ name: p.name, value: originValue })) {
      checkParams.push(p);
    }
  }
  if (checkParams.length <= 0) {
    console.log('没有ssrf参数');
    return;
  }

  const tasks = pooledMap(10, checkParams, async (p) => {
    const { token, domain, error } = await risk.newDNSLogDomain();
    if (error) return;
    let payload = `http://${domain}`;
    let { response: resp, request } = await fuzz.sendModifiedRequest(Object.assign(p, { value: payload }));
    let url = resp.url;
    let urlObj = new URL(url);
    url = `${urlObj.origin}${urlObj.pathname}`;
    let records = await risk.checkDNSLogByToken(token);
    if (records.length > 0) {
      console.log('dnslog回显成功,有可能ssrf');
      let haveHttpReverse = false;
      const { response, token } = await risk.newLocalReverseHTTPUrl();
      let res = await fuzz.sendModifiedRequest(Object.assign(p, { value: risk.genReverseUrl(token) }));
      let reversHttpRecords = await risk.haveReverseRisk(token);
      console.log(reversHttpRecords);
      console.log('http 成功 ssrf漏洞');
      await db.tables.vuln.insertOne({
        url: request.url,
        type: 'ssrf',
        level: VulnerabilityLevel.Medium,
        payload: payload,
        requestRaw: await HttpUtils.dumpRequest(request.clone()),
        responseRow: await HttpUtils.dumpResponse(resp.clone()),
        pluginName,
      });
    }
  });
  await Array.fromAsync(tasks);
}
export default { name: pluginName, endpoint, version: '1.0.0' };

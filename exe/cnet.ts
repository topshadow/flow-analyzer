import { compareTwoStrings } from 'npm:string-similarity';
import db from '@/db/surraldb.ts';
import { resolve } from '@std/path';
import { Subdomain } from '@/schemas/index.tsx';
import { HttpXScanResult } from '@/lib/httpx.ts';

async function getAllSubdomainsTlsKeyworlds() {
    const projectId = 'project:03600c2pmxf3ro6e6dzc';
    const [subdomains] = await db.query<[Subdomain[]]>(
      `select * from subdomain where project_id= $projectId`,
      { projectId },
    );
    
    let allsubdomainsTlsKeyworlds = subdomains
      .filter((s) => s.httpxJson)
      .map((s) => s.httpxJson)
      .filter((j) => j?.tls)
      .map((j) => j.tls)
      .map((tls) => {
        tls.subject_org = tls.subject_org || [];
        return [...tls.subject_an, tls.subject_cn, tls.subject_dn, ...tls.subject_org];
      }).flat().filter((s) => s);
    
    //去重证书
    allsubdomainsTlsKeyworlds = Array.from(new Set(allsubdomainsTlsKeyworlds));
    let cnetoutput = Deno.readTextFileSync(resolve(import.meta.dirname as string, '../tmp/httpx_cnet_output.json'));
    let cnet = JSON.parse(`[${cnetoutput.trim().split('\n').join(',')}]`) as HttpXScanResult[];
    // 过滤掉已有的
    cnet = cnet.filter((c) => !subdomains.filter((s) => s.httpxJson).find((s) => s.httpxJson?.host == c.host));
    let results = [];
    for (let target of cnet) {
      if (target.tls) {
        target.tls.subject_org = target.tls.subject_org || [];
        let targetFingerprint = [
          ...target.tls.subject_an,
          target.tls.subject_cn,
          target.tls.subject_dn,
          ...target.tls.subject_org,
        ].flat().filter((s) => s);
        targetFingerprint = Array.from(new Set(targetFingerprint));
        let isSuccess = check(target, targetFingerprint,allsubdomainsTlsKeyworlds);
        if (isSuccess) {
          results.push(target);
          continue;
        }
      }
    }
    
    console.log('已搜集的隐藏网址', results.length);
    
    console.log(
      '过滤后的',
      results.filter((r) => !subdomains.filter((s) => s.httpxJson).find((s) => s.httpxJson?.host == r.host||s.httpxJson?.a.includes(r.host))).length,
    ); 
    Deno.writeFileSync(resolve(import.meta.dirname as string, '../tmp/httpx_cnet_output_filter.json'), new TextEncoder().encode(results.map((r) => JSON.stringify(r)).join('\n')));
}
await getAllSubdomainsTlsKeyworlds();

async function getHostnameByIP(ip: string): Promise<string[]> {
    try {
      // 将 IP 转换为 PTR 查询格式（如 8.8.8.8 → 8.8.8.8.in-addr.arpa）
    //   const ptr = ip.split('.').reverse().join('.') + '.in-addr.arpa';
      const records = await Deno.resolveDns(ip,  'PTR');
      return records; // 返回第一个 PTR 记录
    } catch (error) {
      console.error("Error:", error.message);
      return [];
    }
  }

function check(target: HttpXScanResult, targetFingerprint: string[],allsubdomainsTlsKeyworlds: string[] = []) {
  for (let f of targetFingerprint) {
    for (let dbf of allsubdomainsTlsKeyworlds) {
      if (compareTwoStrings(f, dbf) >= 0.8) {
        console.log(`找到了隐藏网址${target.host} : 证据目标证书:${f}, 已有证书 ${dbf}`);
        return true;
      }
    }
  }
}

Deno.test('ip by domain',async () => {
    const records = await getHostnameByIP('223.109.81.240');
    console.log(records)
})
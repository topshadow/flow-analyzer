import { Fuzz, str } from '@24wings/core';
import { detectFilteredChars } from './xss-detect.plugin.ts';

Deno.test('xss detect', async () => {
  let fuzz = new Fuzz(new Request('http://localhost:8787/xss/echo?name=admin', { method: 'GET' }));
  let params = fuzz.getAllFuzzableParams();
  const checkStr = str.generateRandomString(6);
  const validStr = str.generateRandomString(8);
  for (let param of params) {
    param.value = checkStr;
    let respStr = await (await fuzz.sendModifiedRequest(param)).text();
    if (respStr.includes(checkStr)) {
      console.log('xss detected');
    }
  }
  console.log(params);
});


Deno.test('查询过滤危险字符', async () => {
    // 使用示例
    const randStr = 'RAND';
    const allDangerousChars = ['<', '>', "'", '"', '/', '-'];
    const testString = 'RANDtest<RAND>RAND\'RAND"RAND/RAND-RANDend';
  
    const filteredChars = detectFilteredChars(testString, randStr, allDangerousChars);
    console.log('Filtered characters:', filteredChars);
  });
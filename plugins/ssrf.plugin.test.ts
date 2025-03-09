import { pooledMap } from '@std/async/pool';
import { assertEquals } from '@std/assert';
import { endpoint } from './ssrf.plugin.ts';

Deno.test('pool map', async () => {
  const results = pooledMap(
    2,
    [1, 2, 3],
    (i) =>
      new Promise((r) =>
        setTimeout(() => {
          console.log(i), r(i);
        }, 3000)
      ),
  );

  assertEquals(await Array.fromAsync(results), [1, 2, 3]);
});

Deno.test('ssrf ', async () => {
  await endpoint(new Request(`http://localhost:8787/ssrf/in-get?url=http%3A%2F%2Fwww.baidu.com%2F`));
});

Deno.test('yak vulnbox post', async () => {
  let request = new Request('http://localhost:8787/ssrf/in-post', {
    'headers': {
      'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
      'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
      'cache-control': 'max-age=0',
      'content-type': 'application/x-www-form-urlencoded',
      'sec-ch-ua': '"Not(A:Brand";v="99", "Microsoft Edge";v="133", "Chromium";v="133"',
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"',
      'sec-fetch-dest': 'document',
      'sec-fetch-mode': 'navigate',
      'sec-fetch-site': 'same-origin',
      'sec-fetch-user': '?1',
      'upgrade-insecure-requests': '1',
    },
    'referrer': 'http://localhost:8787/ssrf/in-post',
    'referrerPolicy': 'strict-origin-when-cross-origin',
    'body': 'name=dasd&email=asd%40qq.com&age=11&url=https%3A%2F%2Ftcberry.deno.dev&gender=&message=sad',
    'method': 'POST',
    'mode': 'cors',
    'credentials': 'omit',
  });
  const client = Deno.createHttpClient({ proxy: { url: 'http://localhost:8083' } });
  await fetch(request.clone(), { client });
  await endpoint(request);
  client.close();
});
let request = new Request('http://localhost:8787/ssrf/in-post', {
  'headers': {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    'cache-control': 'max-age=0',
    'content-type': 'application/x-www-form-urlencoded',
    'sec-ch-ua': '"Not(A:Brand";v="99", "Microsoft Edge";v="133", "Chromium";v="133"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'same-origin',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
  },
  'referrer': 'http://localhost:8787/ssrf/in-post',
  'referrerPolicy': 'strict-origin-when-cross-origin',
  'body': 'name=dasd&email=asd%40qq.com&age=11&url=https%3A%2F%2Ftcberry.deno.dev&gender=&message=sad',
  'method': 'POST',
  'mode': 'cors',
  'credentials': 'omit',
});
const client = Deno.createHttpClient({ proxy: { url: 'http://localhost:8083' } });
await fetch(request.clone(), { client });
await request.clone().formData();
await request.clone().formData();
await request.clone().formData();
await request.clone().formData();
await endpoint(request.clone());
client.close();

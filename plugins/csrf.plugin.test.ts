import { endpointOut } from './csrf.plugin.ts';

Deno.test('csrf', async () => {
});
let req = new Request('http://localhost:8787/csrf/unsafe', {
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
    'cookie': 'vulCookie=confidential_cookie',
    'Referer': 'http://localhost:8787/csrf/unsafe',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
  },
  'referrer': 'http://localhost:8787/csrf/unsafe',
  'referrerPolicy': 'strict-origin-when-cross-origin',
  'body': 'info=asd',
  'method': 'POST',
});
let res = await fetch(req.clone());

await endpointOut(req, res);

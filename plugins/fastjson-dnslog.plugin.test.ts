import { endpoint } from './fastjson-dnslog.plugin.ts';

Deno.test('detect fastjson version', async () => {
    await endpoint(
        new Request('http://localhost:8090/', {
          'method': 'POST',
          'headers': {
            'content-type': 'application/json',
          },
          'body': '{"age":1}',
        }),
      );
});
// await endpoint(
//   new Request('http://localhost:8090/', {
//     'method': 'POST',
//     'headers': {
//       'content-type': 'application/json',
//     },
//     'body': '{"age":1}',
//   }),
// );
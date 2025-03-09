import { endpoint, stackedPayloads } from './sql-stack-query.plugin.ts';

Deno.test('sql-statck-query plugin test', () => {
  let result = stackedPayloads();
  console.log(result);
});

Deno.test('sql-statck-query plugin test plugin', async () => {
  await endpoint(new Request('http://localhost:8787/user/id?id=1'));
});

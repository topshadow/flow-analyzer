import { endpoint } from './sql-union-md5.plugin.ts';

Deno.test("unon md5 test", async () => {
   await endpoint(new Request('http://localhost:8787/user/id?id=1'))
})
import { endpoint } from './sql-error-based.plugin.ts';

Deno.test("sql error test", async () => {
   await  endpoint(new Request(`http://localhost:8787/user/id?id=1`,{method:'get'}))
})

await  endpoint(new Request(`http://localhost:8787/user/id?id=1`,{method:'get'}))
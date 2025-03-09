import { endpoint } from './sql-time-based-blind.plugin.ts';

Deno.test("时间盲注", async () => {
   await endpoint(new Request('http://localhost:8787/user/id?id=1',{method:'get'}));
})
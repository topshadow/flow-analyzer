import { endpoint } from './apach-2017-15715.plugin.ts';

Deno.test("test",async () => {
   await endpoint(new Request(`http://localhost:8787/upload/case/cve-2017-15715`));
})
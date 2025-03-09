import { endpoint } from './ssti.plugin.ts';

Deno.test('ssti get', async () => {
    await endpoint(new Request('http://localhost:8787/expr/injection?a=1'));
});



Deno.test('ssti get json', async () => {
    await endpoint(new Request('http://localhost:8787/expr/injection?b=%7B%22a%22%3A1%7D')); 
})
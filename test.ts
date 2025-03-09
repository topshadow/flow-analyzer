Deno.test('xss echo', async () => {
  let client = Deno.createHttpClient({ proxy: { url: 'http://localhost:8083' } });
  await fetch(`http://localhost:8787/xss/replace/nocase?name=admin`, { client });
});

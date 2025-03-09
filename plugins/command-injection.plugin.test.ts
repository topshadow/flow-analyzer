import { endpoint } from './command-injection.plugin.ts';

Deno.test('command-injection plugin test', async () => {
  await endpoint(new Request(`http://localhost:8787/exec/ping/bash?ip=127.0.0.1`));
  // await endpoint(new Request(`http://localhost:8787/exec/ping/shlex?ip=127.0.0.1`))
});

// await endpoint(new Request(`http://localhost:8787/exec/ping/shlex?ip=127.0.0.1`));

await endpoint(new Request(`http://localhost:8787/exec/ping/bash?ip=127.0.0.1`));

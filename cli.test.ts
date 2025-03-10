import { delay } from "@std/async";
import { ProgressBar } from "@std/cli/unstable-progress-bar";

const gen = async function* () {
  for (let i = 0; i < 100; ++i) {
    yield new Uint8Array(1000).fill(97);
    await delay(Math.random() * 200 | 0);
  }
}();
const writer = (await Deno.create("./_tmp/output.txt")).writable.getWriter();

const bar = new ProgressBar(Deno.stdout.writable, { max: 100_000 });

for await (const buffer of gen) {
  bar.add(buffer.length);
  await writer.write(buffer);
}

await bar.end();
await writer.close();

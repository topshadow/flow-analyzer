import { Hono } from "jsr:@hono/hono";
import xss from "./xss.plugin.ts";
import { assert } from "@std/assert";
import { setupLog } from "../log.ts";
import { xhtml } from "@24wings/core";
const app = new Hono();

function prepareServer(app: Hono<any>) {
  const server = Deno.serve(app.fetch);
  return { server, addr: server.addr, url: `http://localhost:${server.addr.port}` };
}
await setupLog(true);

/**检测 xss url 出现在 text的漏洞 */
Deno.test("xss plugin test in query-text", async () => {
  app.get("/xss-in-url", (c) => {
    return c.html(`<h1>hello ${c.req.query("name")}</h1>`);
  });

  const { server, url } = prepareServer(app);
  const results = await xss.endpoint(new Request(url + "/xss-in-url?name=a"));
  assert(results.length > 0);
  await server.shutdown();
});

Deno.test("xss plugin test in query-script", async () => {
  app.get("/xss", (c) => {
    return c.html(`<html><h1>hello</h1><script>let a='${c.req.query("name")}'</script> </html>`);
  });

  const { server, url } = prepareServer(app);
  const results = await xss.endpoint(new Request(url + "/xss?name=a"));
  assert(results.length > 0);
  await server.shutdown();
});

Deno.test("xss plugin test in query-on-attr", async () => {
  app.get("/xss", (c) => {
    return c.html(`<html><h1 onclick="${c.req.query("name")}">hello</h1> </html>`);
  });
  const { server, url } = prepareServer(app);
  const results = await xss.endpoint(new Request(url + "/xss?name=a"));
  assert(results.length > 0);
  await server.shutdown();
});

Deno.test("xhtml", () => {
  let ps = xhtml.found(`<html> <div> <h1>hello abc</h1> <script>let a='abc' </script> </div> </html>`, "abc");
  console.log(ps[1].node.parentNode.tagName);
});

// app.get("/xss-in-url", (c) => {
//     return c.html(`<div><h1>hello ${c.req.query("name")}</h1><script>let a='${c.req.query("name")}'</script></div>`);
//   });
//   const { server, url } = prepareServer(app);
// const r= await xss.endpoint(new Request(url + "/xss-in-url?name=a"));
// console.log(r);

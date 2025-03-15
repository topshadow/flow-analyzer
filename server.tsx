import { Hono } from "hono";
import { cors } from "hono/cors";
import { surrealDbFetch } from "./sdb.ts";
const app = new Hono();
app.use("*", cors());
app.get("/", (c) => {
  return c.json({ ok: "Hello Hono!" });
});
app.post("/db", async (c) => {
  const { sql } = await c.req.json();
  console.log(sql);
  return c.json(
    await surrealDbFetch(sql),
  );
});

export default app;

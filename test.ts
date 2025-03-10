import Surreal from "https://deno.land/x/surrealdb/mod.ts";
import { surrealdbDenoEngines } from "https://deno.land/x/surrealdb.deno/mod.ts";

// Enable the WebAssembly engines
const db = new Surreal({
    engines: surrealdbDenoEngines(),
});

// Now we can start SurrealDB as an in-memory database
await db.connect("mem://");
// Or we can start a persisted SurrealKV database
await db.connect("surrealkv://demo");

// Now use the JavaScript SDK as normal.
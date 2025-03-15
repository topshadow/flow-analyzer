import { preload, unload, Webview } from "jsr:@webview/webview";
import { surrealDbFetch } from "./sdb.ts";
await preload();
const webview = new Webview();
//s
webview.bind("hello", (str) => ({ hello: str }));
webview.bind("dbQuery", (str) => ( surrealDbFetch(str)));

webview.navigate("http://localhost:5173");
webview.run();
unload();

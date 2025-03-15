import { extract_info } from "./mod.ts";

Deno.test("findsomething", () => {
    let r = extract_info(`md5 password:123456 
        location.href = "/"  <a href="/adsda">baidu</a`);
    console.log(r)
})
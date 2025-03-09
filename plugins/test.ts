Deno.test("async",async ()=>{
   let client= Deno.createHttpClient({proxy:{url:'http://localhost:8083'}})
   await (await fetch(`http://localhost:8787/user/id?id=1`, { client })).text();
   client.close()
})
import { getLocal } from  'mockttp';
const server = getLocal();
getLocal().forAnyRequest().thenPassThrough();
server.start(8080);
server.on('request', (req) => {
  console.log(req.method, req.url);
});
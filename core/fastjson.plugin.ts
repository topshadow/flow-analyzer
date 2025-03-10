import { Fuzz, FuzzParam, HttpUtils, ParamType ,str} from '@24wings/core';
const pluginName ='fastjson';

export async function endpoint(request: Request) {
//   const fuzz =await  Fuzz.fromRequest(request);
//   const response = await await fuzz.sendOriginalRequest();
//   let originRequest = await HttpUtils.dumpRequest(request);
//   let params: FuzzParam[] = [];
//   const reqIsJson = request.headers.get('Content-Type')?.toLowerCase().includes('json') ?? false;

//   // 假设你也有一个 response 对象
//     const rspIsJson = response.headers.get('Content-Type')?.toLowerCase().includes('json') ?? false;
//     if (reqIsJson) {
//         console.log('请求中是json')
//     }
//     if (rspIsJson) {
//         console.log('响应中是json')
//     }
//     // fuzz query,form,cookie
//     if (!reqIsJson && !rspIsJson) {
//         params = fuzz.getAllParams().filter(p => [ParamType.FORM, ParamType.JSON, ParamType.QUERY, ParamType.COOKIE].includes(p.position));
//         let needToFuzzParams:FuzzParam[]=[]
//         for (let p of params) {
//             let value = p.value;
//             if (p.isArray) {
//                 if ((p.value as any[]).length > 0) {
//                     p.value=p.value[0]
//                 } else {
//                     continue;
//                }
//             }
//             if (str.isJson(value as string)) {
//                     needToFuzzParams.push({...p,value:value})
//             }
            

//         }
//     }
//     // json
//     else {
        
//     }

}
export default {name:pluginName,version:'1.0.0',endpoint}
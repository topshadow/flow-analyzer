// FILEPATH: e:/deno_mitm/plugins/flow-analyzer/plugins/csrf.ts

import { DOMParser, Element } from 'https://deno.land/x/deno_dom/deno-dom-wasm.ts';
import {poc } from '@24wings/core';
interface Result {
  url: string;
  req: Request;
  rsp: Response;
}

const paramBlackList = ['token', 'csrf', 'xsrf', 'tkn'];
const submitBlackList = ['login', 'register', 'search', '登录', '注册', '搜索'];

function newResult(url: string, req: Request, rsp: Response): Result {
  return { url, req, rsp };
}

function csrfLog(result: Result) {
  console.log('CSRF vulnerability detected:', result.url);
  // 在这里实现您的日志记录逻辑
}

function formCheck(url: string, req: Request, rsp: Response, form: Element) {
  // 检测是否是受js控制的表单 ， 没有action，且有id
  const action = form.getAttribute('action') || '';
  const id = form.getAttribute('id') || '';
  if (action === '' && id !== '') {
    return;
  }

  const inputs = form.querySelectorAll('input');

  for (const input of inputs) {
    if (!input.hasAttribute('hidden')) {
      continue;
    }
    const inputName = input.getAttribute('name') || '';
    for (const name of paramBlackList) {
      if (inputName.toLowerCase().includes(name)) {
        return;
      }
    }
  }

  const interHtml = form.outerHTML;
  // for (const name of submitBlackList) {
  //   if (interHtml.toLowerCase().includes(name)) {
  //     return;
  //   }
  // }

  csrfLog(newResult(url, req, rsp));
}

// 使用示例
// async function checkCSRF(url: string, req: Request, rsp: Response, body: string) {
//   const parser = new DOMParser();
//   const doc = parser.parseFromString(body, 'text/html');

//   if (!doc) {
//     console.log('无法解析 HTML');
//     return;
//   }

//   const forms = doc.querySelectorAll('form');
//   for (const form of forms) {
//     formCheck(url, req, rsp, form);
//   }
// }

async function corsCheck(req: Request, rsp: Response, url: string) {
  // 检查是否为跨域请求以及请求是否有效
  if (rsp.status !== 200 || !req.headers.get('Origin')) {
    return;
  }

  if (!rsp.headers.get('Access-Control-Allow-Origin') || rsp.headers.get('Content-Length') === '0') {
    return;
  }

  if (rsp.headers.get('Access-Control-Allow-Origin') === '*') {
    console.log('可跨任意域*');
  }

  const domain = `${Math.random().toString(36).substring(7)}.example.com`;

  // 创建一个新的请求，模拟来自不同域的请求
  const newReq = new Request(req, {
    headers: new Headers(req.headers),
  });
  newReq.headers.set('Origin', domain);

  try {
    const lowHttp = await fetch(newReq);
    const newHeaders = lowHttp.headers;

    if (newHeaders.get('Access-Control-Allow-Origin')) {
      if (newHeaders.get('Access-Control-Allow-Origin')?.includes(domain)) {
        // corsLog(newResult(url, req, rsp));
        console.log('可跨子域名');
      }
    }
  } catch (err) {
    console.error('Error:', err);
  }
}

export async function endpointOut(req: Request, res: Response) {
  const body = await res.text();
  corsCheck(req, res, req.url);
  // checkCSRF(req.url, req, res, body);
  // 如果 headers 是一个普通的 JavaScript 对象
  let contentType = res.headers.get('Content-Type') || '';
  if (!contentType || !contentType.includes('html')) {
    return;
  }
  await csrfDetect(req.url,req,res,body,)


}


async function csrfDetect(url: string, req: Request, rsp: Response, body: string) {
  // 假设我们有一个自定义的 HTTPEx 函数来模拟 Yak 的 poc.HTTPEx
  const noCookie = req.clone();
  noCookie.headers.delete('cookie');
  const {response:rspWithoutCookie,duration} = await poc.httpEx(req);
  
  

  const parser = new DOMParser();
  const phtml = parser.parseFromString(body, "text/html");
  const html = parser.parseFromString(await rspWithoutCookie.text(), "text/html");

  if (!phtml || !html) {
    console.error("Failed to parse HTML");
    return;
  }

  const pforms = phtml.querySelectorAll("form");
  const forms = html.querySelectorAll("form");

  const dforms: Element[] = [];
  pforms.forEach(pform => {
    let flag = true;
    forms.forEach(form => {
      if (formCompare(pform as Element, form as Element)) {
        flag = true;
      }
    });
    if (flag) {
      dforms.push(pform as Element);
    }
  });

  for (const form of dforms) {
    await formCheck(url, req, rsp, form);
  }
}
function formCompare(pform: Element, form: Element): boolean {
  const paction = pform.getAttribute("action") || "";
  const action = form.getAttribute("action") || "";
  
  if (paction !== action) {
    return false;
  }

  const pinputs = pform.querySelectorAll("input");
  const inputs = form.querySelectorAll("input");
  
  if (pinputs.length !== inputs.length) {
    return false;
  }

  for (let i = 0; i < pinputs.length; i++) {
    const pinputName = pinputs[i].getAttribute("name") || "";
    const inputName = inputs[i].getAttribute("name") || "";
    
    if (pinputName !== inputName) {
      return false;
    }
  }

  return true;
}
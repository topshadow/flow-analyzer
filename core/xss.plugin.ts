import { Fuzz, type FuzzParam, HttpUtils, js, str, xhtml } from "jsr:@24wings/core@0.1.5";
import { getLogger } from "@logtape/logtape";
const log = getLogger(["plugin", "xss"]);

import type { PluginResult } from "../result.ts";

interface Payload {
  value: string;
  dangerousChars: string;
  payloadType: "js" | "spec-attr" | "tag" | "attr" | "comment";
}
async function endpoint(request: Request): Promise<PluginResult[]> {
  const fuzz = await Fuzz.fromRequest(request);
  log.debug("开始xss 测试 for:" + request.url);
  const params = fuzz.getAllFuzzableParams();
  log.debug("参数长度:" + params.length);
  const results: PluginResult[] = [];
  for (const param of params) {
    results.push(...await fuzzParam(param, fuzz, request));
  }
  return results;
}

async function fuzzParam(param: FuzzParam, fuzz: Fuzz, request: Request): Promise<PluginResult[]> {
  const checkResults: PluginResult[] = [];
  const checkStr = str.generateRandomString(6);
  const verfiyRandomStr = str.generateRandomString(8);
  param.value = checkStr;
  const resp = await (await fuzz.sendModifiedRequest(param)).response;
  const respStr = await resp.clone().text();
  const payloads: Payload[] = [];
  if (respStr.includes(checkStr)) {
   const positions= xhtml.found(respStr, checkStr)
    for (const position of positions) {
      if (position.position == xhtml.StringPosition.TEXT) {
        payloads.push({
          value: `</${str.randomUpperAndLower(position.node?.parentNode?.nodeName || "")}><${str.randomUpperAndLower("img")} id='${verfiyRandomStr}' src=1 onerror='prompt(1)'><${
            str.randomUpperAndLower(position.node?.parentNode?.nodeName || "")
          }>`,
          dangerousChars: "<>",
          payloadType: "tag",
        });
      } else if (position.position == xhtml.StringPosition.SCRIPT) {
        const tagName = "script";
        // 引号判断
        const matchText = position.node.textContent;
        const randStrIndex = matchText.indexOf(checkStr);

        // 逆向查找引号类型
        let quote = "";
        let currentIndex = randStrIndex - 1;
        while (currentIndex >= 0) {
          const char = matchText[currentIndex];

          if (char === "=") break;
          if (['"', "'", "`"].includes(char)) {
            quote = char;
            break;
          }
          currentIndex--;
        }
        // 生成JS注入payload
        const jsPayload: Payload = {
          value: `1${quote};prompt('${verfiyRandomStr}');${quote}`,
          dangerousChars: ";" + quote,
          payloadType: "js",
        };
        payloads.push(jsPayload);

        const payload = `1${quote};</${str.randomUpperAndLower(tagName)}><${str.randomUpperAndLower("img")} id='${verfiyRandomStr}' src=1 onerror='prompt(1)'><${
          str.randomUpperAndLower(tagName)
        }>${quote}`;

        payloads.push({ value: payload, dangerousChars: "<>" + quote, payloadType: "js" });
      } else if (position.position == xhtml.StringPosition.ATTRIBUTE) {
        if (position.attributeName) {
          let attributeName = position.attributeName.toUpperCase();
          if (specialAttr(attributeName)) {
            let payloadValue = specialAttrPayload(attributeName, verfiyRandomStr);
            payloads.push({ value: payloadValue, dangerousChars: "", payloadType: "spec-attr" });
          } else {
            let nodeName = str.randomUpperAndLower(position.node?.nodeName || "");
            let payload = `"></${str.randomUpperAndLower(position.node?.nodeName || "")}><${str.randomUpperAndLower("img")} id='${verfiyRandomStr}' src=1 onerror='prompt(1)'><${
              str.randomUpperAndLower(position.node?.nodeName || "")
            } ${position.node?.nodeName}="`;
            payloads.push({ value: payload, dangerousChars: "<>/", payloadType: "attr" });

            payload = `'></${str.randomUpperAndLower(position.node?.nodeName || "")}><${str.randomUpperAndLower("img")} id='${verfiyRandomStr}' src=1 onerror='prompt(1)'><${nodeName} ${nodeName}='`;
            payloads.push({ value: payload, dangerousChars: "<>/", payloadType: "attr" });

            payload = `></${str.randomUpperAndLower(position.node?.nodeName || "")}><${str.randomUpperAndLower("img")} id='${verfiyRandomStr}' src=1 onerror='prompt(1)'><${
              str.randomUpperAndLower(nodeName)
            } ${nodeName}=`;
            payloads.push({ value: payload, dangerousChars: "<>/", payloadType: "attr" });
          }
        }
      }
    }

    // ! 四 检测危险字符并过滤payload
    let filterChars: string[] = [];
    const allDangerousChars = ["<", ">", "'", '"', "/", "-"];
    let i = 0;

    let detectPayload = checkStr + allDangerousChars.join(checkStr) + checkStr;
    let cloneParam = { ...param, value: detectPayload } as FuzzParam;
    const resp = await fuzz.sendModifiedRequest(cloneParam);
    const respText = await (await resp.response).clone().text();
    filterChars = detectFilteredChars(respText, checkStr, allDangerousChars);
    log.debug("生成的payload {payloads}", { payloads });
    for (let payload of payloads) {
      let isFilter = false;
      for (const filterChar of filterChars) {
        if (payload.dangerousChars.includes(filterChar)) {
          isFilter = true;
        }

        if (isFilter) {
          // 如果被过滤了，就将有回显的位置payload写入数据库中，防止误报
          // EchoLog(newResult(false, url, param, payload, reqBody, rawBody))
          log.info("有过滤");
          continue;
        }
      }

      let res = await fuzz.sendModifiedRequest({ ...param, value: payload.value });
      let resText = await (await res.response).clone().text();
      let matchedNodes = xhtml.found(resText, verfiyRandomStr);
      let existVuln = false;
      let maybeVuln = false;
      if (payload.payloadType == "js") {
        for (let node of matchedNodes) {
          if (
            // node.node?.parentNode?.nodeName?.toLocaleLowerCase() == "script" ||
            node.position==xhtml.StringPosition.SCRIPT
          ) {
            let scriptNode = node.node?.parentNode?.nodeName?.toLocaleLowerCase() == "script" ? node.node.parentNode : node.node;
            let { error, stringLiterals } = js.astWalk(scriptNode.textContent || "");
            if (error) {
              //如果ast报错 则有漏洞

              existVuln = true;
              maybeVuln = true;
            }
            if (stringLiterals.includes(verfiyRandomStr)) {
              existVuln = true;
            }
          }
        }
      } else {
        if (payload.payloadType == "comment") {
          const results = xhtml.found(resText, verfiyRandomStr);
          for (const item of results) {
            if (item.position === xhtml.StringPosition.TEXT) {
              existVuln = true;
              maybeVuln = true;
            }
          }
        } else if (payload.payloadType.startsWith("spec")) {
          // ! 对spec-attr类型的漏洞不做判断,可能存在误报
          existVuln = true;
          maybeVuln = true;
        } else { // tag或attr类型的payload判断漏洞存在条件: 存在属性值为verifyRandStr的节点，证明标签逃逸或者属性逃逸
          const results = xhtml.found(resText, verfiyRandomStr);
          for (const item of results) {
            if (
              item.position == xhtml.StringPosition.ATTRIBUTE && item.attributeName?.toLowerCase() == "id" &&
              item.node?.getAttribute("id") == verfiyRandomStr
            ) {
              existVuln = true;
              maybeVuln = true;
            }
          }
        }
      }

      if (existVuln || maybeVuln) {
        checkResults.push({
          url: request.url,
          payload: payload.value,
          level: "medium",
          type: "xss",
          requestRaw: await HttpUtils.dumpRequest(res.request.clone()),
          responseRow: await HttpUtils.dumpResponse((await res.response).clone()),
          description: "xss漏洞",
          pluginName: "xss",
        });

        // log.debug(`existVuln:${existVuln} , maybeVuln:${maybeVuln},paylod:${payload.value}`);
      }
    }
  }
  return checkResults;
}

export function detectFilteredChars(randStrFromIndex: string, randStr: string, allDangerousChars: string[]): string[] {
  let i = 0;
  const filterChars: string[] = [];

  while (true) {
    const [n, btChr] = xhtml.matchBetween(randStrFromIndex, randStr, randStr, 50);
    if (n === -1 || i >= allDangerousChars.length) {
      break;
    }

    if (allDangerousChars[i] !== btChr) {
      filterChars.push(allDangerousChars[i]);
    }

    randStrFromIndex = randStrFromIndex.slice(n + randStr.length);
    i++;
  }

  return filterChars;
}

export function specialAttr(attrName: string): boolean {
  attrName = attrName.toUpperCase();

  const specialAttrs = new Set([
    "ONAFTERPRINT",
    "ONBEFOREPRINT",
    "ONBEFOREONLOAD",
    "ONBLUR",
    "ONERROR",
    "ONFOCUS",
    "ONHASCHANGE",
    "ONLOAD",
    "ONMESSAGE",
    "ONOFFLINE",
    "ONONLINE",
    "ONPAGEHIDE",
    "ONPAGESHOW",
    "ONPOPSTATE",
    "ONREDO",
    "ONRESIZE",
    "ONSTORAGE",
    "ONUNDO",
    "ONUNLOAD",
    "ONCHANGE",
    "ONCONTEXTMENU",
    "ONFORMCHANGE",
    "ONFORMINPUT",
    "ONINPUT",
    "ONINVALID",
    "ONRESET",
    "ONSELECT",
    "ONSUBMIT",
    "ONKEYDOWN",
    "ONKEYPRESS",
    "ONKEYUP",
    "ONCLICK",
    "ONDBLCLICK",
    "ONDRAG",
    "ONDRAGEND",
    "ONDRAGENTER",
    "ONDRAGLEAVE",
    "ONDRAGOVER",
    "ONDRAGSTART",
    "ONDROP",
    "ONMOUSEDOWN",
    "ONMOUSEMOVE",
    "ONMOUSEOUT",
    "ONMOUSEOVER",
    "ONMOUSEUP",
    "ONMOUSEWHEEL",
    "ONSCROLL",
    "ONABORT",
    "ONCANPLAY",
    "ONCANPLAYTHROUGH",
    "ONDURATIONCHANGE",
    "ONEMPTIED",
    "ONENDED",
    "ONLOADEDDATA",
    "ONLOADEDMETADATA",
    "ONLOADSTART",
    "ONPAUSE",
    "ONPLAY",
    "ONPLAYING",
    "ONPROGRESS",
    "ONRATECHANGE",
    "ONREADYSTATECHANGE",
    "ONSEEKED",
    "ONSEEKING",
    "ONSTALLED",
    "ONSUSPEND",
    "ONTIMEUPDATE",
    "ONVOLUMECHANGE",
    "ONWAITING",
    "ONTOUCHSTART",
    "ONTOUCHMOVE",
    "ONTOUCHEND",
    "ONTOUCHENTER",
    "ONTOUCHLEAVE",
    "ONTOUCHCANCEL",
    "ONGESTURESTART",
    "ONGESTURECHANGE",
    "ONGESTUREEND",
    "ONPOINTERDOWN",
    "ONPOINTERUP",
    "ONPOINTERCANCEL",
    "ONPOINTERMOVE",
    "ONPOINTEROVER",
    "ONPOINTEROUT",
    "ONPOINTERENTER",
    "ONPOINTERLEAVE",
    "ONGOTPOINTERCAPTURE",
    "ONLOSTPOINTERCAPTURE",
    "ONCUT",
    "ONCOPY",
    "ONPASTE",
    "ONBEFORECUT",
    "ONBEFORECOPY",
    "ONBEFOREPASTE",
    "ONAFTERUPDATE",
    "ONBEFOREUPDATE",
    "ONCELLCHANGE",
    "ONDATAAVAILABLE",
    "ONDATASETCHANGED",
    "ONDATASETCOMPLETE",
    "ONERRORUPDATE",
    "ONROWENTER",
    "ONROWEXIT",
    "ONROWSDELETE",
    "ONROWINSERTED",
    "ONSELECTSTART",
    "ONHELP",
    "ONBEFOREUNLOAD",
    "ONSTOP",
    "ONBEFOREEDITFOCUS",
    "ONSTART",
    "ONFINISH",
    "ONBOUNCE",
    "ONPROPERTYCHANGE",
    "ONFILTERCHANGE",
    "ONLOSECAPTURE",
    "ONDRAGDROP",
    "ONDRAGEXIT",
    "ONDRAGGESTURE",
    "ONCLOSE",
    "ONCOMMAND",
    "ONOVERFLOW",
    "ONOVERFLOWCHANGED",
    "ONUNDERFLOW",
    "ONPOPUPHIDDEN",
    "ONPOPUPHIDING",
    "ONPOPUPSHOWING",
    "ONPOPUPSHOWN",
    "ONBROADCAST",
    "ONCOMMANDUPDATE",
    "STYLE",
  ]);

  return specialAttrs.has(attrName);
}

export function specialAttrPayload(attrName: string, verifyRandStr: string): string {
  let payload = "";

  if (attrName.toUpperCase() === "STYLE") {
    payload = `xss: expression(prompt(\`${verifyRandStr}\`))`;
  } else {
    payload = `prompt(\`${verifyRandStr}\`)`;
  }

  return payload;
}

export default { name: "xss", version: "321", endpoint };

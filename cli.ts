import { parseArgs } from "jsr:@std/cli/parse-args";
import { har, httpUtil } from "@24wings/core";
import {  getLogger } from "jsr:@logtape/logtape";
import { setupLog } from "./log.ts";
import * as colors from "jsr:@std/fmt/colors";
import { PluginResult } from "./result.ts";


function printHelp() {
  log.info(`
${colors.green("流量分析器 (flow-analyzer)")} v0.1.0
${colors.blue("网络流量分析和安全检测工具")}

${colors.yellow("用法:")}
  flow-analyzer <命令> [选项]

${colors.yellow("命令:")}
  ${colors.white("start")}         启动流量分析器
  ${colors.white("list-plugins")}  列出所有可用的插件
  ${colors.white("test")}          运行测试
${colors.yellow("选项:")}
  ${colors.white("-h, --help")}     显示帮助信息
  ${colors.white("-v, --version")}  显示版本信息
  ${colors.white("-i, --input")}    输入流量文件路径 (HAR格式)
  ${colors.white("-j, --json")}     输出为JSON格式的扫描结果
  ${colors.white("--log-level")}    日志级别 ("error" | "debug" | "info" | "warning" | "fatal" | null | undefined), 默认: debug 但是没有启用日志
  ${colors.white("--plugins")}      要加载的插件列表, 例如: --plugins=xss,sql-injection
  `);
}

const log = getLogger(["cli"]);
// 定义帮助信息

function printVersion() {
  log.info("flow-analyzer v0.1.0");
}
// 列出插件
function listPlugins() {
  log.info(colors.blue("可用插件:"));
  const plugins = [
    "sql-injection",
    "xss-detection",
    "csrf-detection",
    "command-injection",
    "file-upload",
    "ssrf-detection",
    "ssti-detection",
    "fastjson",
    "apache-cve-2017-15715",
    "sensitive-data",
  ];

  plugins.forEach((plugin, index) => {
    log.info(`${colors.green(index + 1 + ".")} ${colors.yellow(plugin)}`);
  });
}


// 启动分析器
async function startAnalyzer(options: {
  input?: string;
  plugins?: string[];
  logLevel?: string;
  json?:boolean
}) {
  try {
    // 处理输入流量
    let jsonString = ""; // 声明 jsonString 变量，用于存储 HAR JSON 字符串
    let inputData;
    let parsedHarData: har.Har;

    if (options.input) {
      // 从文件读取
      try {
        jsonString = await Deno.readTextFile(options.input);
        console.log(colors.blue(`已从文件 ${options.input} 读取流量数据`));
      } catch (error) {
        console.error(colors.red(`读取输入文件失败: ${error.message}`));
        Deno.exit(1);
      }
    } else {
      const decoder = new TextDecoder();
      let text = "";
      for await (const chunk of Deno.stdin.readable) {
        text += decoder.decode(chunk);
      }
      jsonString = text;
    }
    if (options.plugins) {
      const plugin = await import("./core/xss.plugin.ts") ;
      const result = har.harToHttpText(jsonString);
      const scanResult:PluginResult[]=[]
      for (const { request, response } of result) {
       scanResult.push(...await plugin.default!.endpoint(await httpUtil.parseRequest(request)));
        // await plugin.default!.endpointOut(await HttpUtils.parseRequest(request),await HttpUtils.parseResponse(response));
      }
      if(options.json){
        console.log(scanResult)
      }
    }
  } catch (error) {
    console.error(colors.red("启动失败:"), error);
    Deno.exit(1);
  }
}


async function main() {
  // 解析命令行参数
  const args = parseArgs(Deno.args, {
    boolean: ["help", "version","json"],
    string: ["input", "log-level", "plugin",],
    alias: {
      h: "help",
      v: "version",
      i: "input",
      l:"log-level",
      j:"json"
    },
    default: {
      "log-level": "info",
    },
  });

  // 处理插件列表
  let plugins: string[] = [];
  if (typeof args.plugins === "string") {
    plugins = args.plugins.split(",");
  }

  // 处理命令
  const command = args._[0];

  // 显示帮助信息
  if (args.help) {
    printHelp();
    return;
  }

  // 显示版本信息
  if (args.version) {
    printVersion();
    return;
  }
  if(args["log-level"]){
    await setupLog(true,args["log-level"] as any)
  }
  // 根据命令执行相应的操作
  switch (command) {
    case "start":
      await startAnalyzer({
        input: args.input,
        plugins,
        logLevel: args["log-level"],
        json:args["json"]
      });
      break;
    case "list-plugins":
      listPlugins();
      break;

    default:
      // 如果没有提供命令或提供了未知命令，显示帮助信息
      printHelp();
      break;
  }
}

// 执行主函数
await main();


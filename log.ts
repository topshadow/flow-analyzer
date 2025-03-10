import { configure, getConsoleSink } from "jsr:@logtape/logtape";
export async function setupLog(enable:boolean, logLevel:"error" | "debug" | "info" | "warning" | "fatal" | null | undefined="debug") {
    const defaultFilter= enable?[] :['noLog'];
    await configure({
      sinks: { console: getConsoleSink() },
      loggers: [
        { category: ["logtape", "meta"], sinks: [] },
  
        { category: "plugin", lowestLevel: logLevel, sinks: ["console"],filters:defaultFilter },
        { category: "cli", lowestLevel: logLevel, sinks: ["console"],filters:defaultFilter  },
        // { category: ['core','fuzz'], lowestLevel: "debug", sinks: ["console"] },
      ],
      filters: {
        noLog() {
          return false;
        },
      },
    });
  }
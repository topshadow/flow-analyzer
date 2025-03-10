export type PluginResult = {
  url: string;
  payload: string;
  level: "info" | "low" | "medium" | "high";
  type: string;
  requestRaw: string;
  responseRow: string;
  description: string;
  pluginName: string;
};

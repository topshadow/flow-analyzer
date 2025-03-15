import { extractVersion } from "./re.ts";

export interface Extractor {
  uri?: string[];
  filecontent?: string[];
  func?: string[];
    filename?: string[]
    filecontentreplace?:string[]
}

export interface Vulnerability {
  // below: string;
  atOrAbove?: string;
  severity: string;
  identifiers: { [key: string]: string[] };
  info: string[];
  ranges:{below?:string,atOrAbove?:string}[]
}

export interface Rule {
  vulnerabilities: Vulnerability[];
  extractors: Extractor;
}

export interface Rules {
  [key: string]: Rule;
}

interface DetectedVulnerability {
  component: string;
  version: string;
  vulnerabilities: {
    severity: string;
    info: string[];
  }[];
}

function compareVersions(v1: string, v2: string): number {
  console.log("v2:", v2);

  const parts1 = v1.split(".").map(Number);
  const parts2 = v2.split(".").map(Number);
  for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
    const part1 = parts1[i] || 0;
    const part2 = parts2[i] || 0;
    if (part1 > part2) return 1;
    if (part1 < part2) return -1;
  }

  return 0;
}

export async function scanHtml(html: string): Promise<DetectedVulnerability[]> {
  const rules = await loadRules(import.meta.resolve("./jsrepository-master.json").replace("file:///", ""));
  const detectedVulnerabilities: DetectedVulnerability[] = [];

  for (const [component, rule] of Object.entries(rules)) {
    const { extractors, vulnerabilities } = rule as Rule;

    if (extractors.filename||extractors.filecontent) {
      const allPattern=[...extractors.filename||[],...extractors.filecontent||[],...extractors.filecontentreplace||[]];
      for (const pattern of allPattern) {
        const version = extractVersion(html, pattern);
        // console.log(String.raw`${pattern}`, version);
          // 提取版本
          if (version) {
            const detectedVulns = vulnerabilities
            // 过滤掉版本以下
            .filter((vuln) =>
              vuln.ranges[0].below? compareVersions(version, vuln.ranges[0].below) < 0 : true
            )
            // 过滤只保留版本以上
            .filter((vuln) =>
              vuln.ranges[0].atOrAbove? compareVersions(version, vuln.ranges[0].atOrAbove) >= 0 : true
            )
            
            ;
            if (detectedVulns.length > 0) {
              detectedVulnerabilities.push({
                component,
                version: version,
                vulnerabilities: detectedVulns.map((v) => ({
                  severity: v.severity,
                  info: v.info,
                })),
              });
            }
          }
      }
    }
  }

  return detectedVulnerabilities;
}

export async function loadRules(path: string) {
  const content = await Deno.readTextFile(path);
  const rules = JSON.parse(content, (key, value) => {
    // 对 filename 和 filecontent 字段进行特殊处理
    if (key === 'filename' || key === 'filecontent' || key === 'uri') {
      return Array.isArray(value) ? value.map(pattern => String.raw`${pattern}`) : value;
    }
    return value;
  });
  return rules;
}

// FILEPATH: test_rules.ts



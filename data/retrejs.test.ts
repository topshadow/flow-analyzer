import { assertEquals } from "@std/assert";
import { loadRules, Rule, scanHtml } from "./retrejs.ts";
import { extractVersion } from "./re.ts";

Deno.test("Load and validate rules", async () => {
  const rules = await loadRules(import.meta.resolve("./jsrepository-master.json").replace("file:///", ""));

  // 检查是否成功加载规则
  assertEquals(typeof rules, "object");
  assertEquals(Object.keys(rules).length > 0, true);

  // 检查一些特定的规则
  //   assertEquals(rules.hasOwnProperty("jquery"), true);
  //   assertEquals(rules.hasOwnProperty("angular"), true);

  // 检查 jquery 规则的结构
  const jqueryRule = rules.jquery;
  assertEquals(Array.isArray(jqueryRule.vulnerabilities), true);
  assertEquals(typeof jqueryRule.extractors, "object");

  // 检查提取器
  const extractors = jqueryRule.extractors;
  assertEquals(Array.isArray(extractors.uri), true);
  assertEquals(Array.isArray(extractors.filecontent), true);
  // console.log(jqueryRule);

  assertEquals(Array.isArray(extractors.func), true);

  // 检查漏洞
  const vulnerability = jqueryRule.vulnerabilities[0];
  //   assertEquals(typeof vulnerability.below, "string");
  assertEquals(typeof vulnerability.severity, "string");
  assertEquals(typeof vulnerability.identifiers, "object");
  assertEquals(Array.isArray(vulnerability.info), true);

  console.log("All tests passed!");
});


// 简单的版本比较函数


Deno.test("Scan HTML for vulnerabilities", async () => {
  // 使用示例
  const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
</head>
<body>
  <h1>Test Page</h1>
</body>
</html>
`;


  let vulnerabilities = await scanHtml(htmlContent// 
  );

  console.log(vulnerabilities);
});



Deno.test("scanHtml should detect jQuery vulnerabilities", async () => {
  // 准备测试数据
  const testCases = [
    {
      name: "jQuery 1.12.4 (vulnerable version)",
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
        </head>
        <body></body>
        </html>
      `,
      expectedVersion: "1.12.4",
      shouldHaveVulnerabilities: true
    },
    {
      name: "jQuery 3.6.0 (safe version)",
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
        </head>
        <body></body>
        </html>
      `,
      expectedVersion: "3.6.0",
      shouldHaveVulnerabilities: false
    },
    {
      name: "No jQuery",
      html: `
        <!DOCTYPE html>
        <html>
        <head></head>
        <body></body>
        </html>
      `,
      expectedVersion: null,
      shouldHaveVulnerabilities: false
    },
    {
      name: "Multiple jQuery versions",
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
          <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
        </head>
        <body></body>
        </html>
      `,
      expectedVersion: "1.12.4",
      shouldHaveVulnerabilities: true
    }
  ];

  for (const testCase of testCases) {
    console.log(`Running test: ${testCase.name}`);
    
    const result = await scanHtml(testCase.html);
    
    if (testCase.shouldHaveVulnerabilities) {
      assertEquals(result.length > 0, true, "Should detect vulnerabilities");
      if (result.length > 0) {
        assertEquals(result[0].component, "jquery");
        assertEquals(result[0].version, testCase.expectedVersion);
        assertEquals(Array.isArray(result[0].vulnerabilities), true);
        assertEquals(result[0].vulnerabilities.length > 0, true);
      }
    } else {
      assertEquals(result.length, 0, "Should not detect vulnerabilities");
    }
  }
});

// 测试无效的 HTML 内容
Deno.test("scanHtml should handle invalid input", async () => {
  const invalidCases = [
    "",
    "not html",
    "<script>invalid</script>",
    null,
    undefined
  ];

  for (const invalidInput of invalidCases) {
    // @ts-ignore
    const result = await scanHtml(invalidInput);
    assertEquals(Array.isArray(result), true, "Should return an array");
    assertEquals(result.length, 0, "Should return empty array for invalid input");
  }
});
/**
 * 将包含 §§version§§ 占位符的模式字符串转换为正则表达式
 * @param pattern 包含版本号占位符的模式字符串
 * @returns 返回一个正则表达式对象
 */
export function createVersionRegex(pattern: string): RegExp {
    // 将 §§version§§ 替换为版本号的捕获组
    const regexStr = pattern
 
      .replaceAll('(§§version§§)', '(\\d+\\.\\d+\\.\\d+(?:-(?:alpha|beta|rc)\\d*)?)')  // 支持版本号格式
      // .replace('\\','')
      // .replace('\\','')
      ;
    return new RegExp(regexStr);
}
  
  /**
   * 从文件名中提取版本号
   * @param filename 文件名
   * @param pattern 包含版本号占位符的模式字符串
   * @returns 提取到的版本号，如果没有匹配则返回 null
   */
  export function extractVersion(filename: string, pattern: string): string | null {
    const regex = createVersionRegex(pattern);
    const match = filename.match(regex);
    return match ? match[1] : null;
  }
  
  // 使用示例：
Deno.test('extractVersion', () => {
    const pattern = "retire-example-($$version$$)(.min)?\\.js";
    
    const testFiles = [
      "2retire-example-1.0.0.js",
      "retire-example-1.0.0.min.js",
      "retire-example-2.1.3-beta1.js",
      "retire-example-2.1.3-rc2.min.js",
      "invalid-file.js"
    ];
  
    for (const file of testFiles) {
      const version = extractVersion(file, pattern);
      console.log(`File: ${file}`);
      console.log(`Version: ${version ?? 'Not found'}`);
      console.log('---');
    }
  })
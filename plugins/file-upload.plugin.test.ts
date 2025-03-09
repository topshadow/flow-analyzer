// 导入所需的Deno模块
import {} from '@std/streams/';
import { basename, extname, resolve } from '@std/path';
import { contentType } from '@std/media-types';
import { endpoint } from './file-upload.plugin.ts';
async function uploadFile(filePath: string, uploadUrl: string) {
  try {
    // 读取文件
    const file = await Deno.open(filePath);
    const fileInfo = await file.stat();
    // 创建FormData对象
    const formData = new FormData();
    let filename = basename(filePath);
    const fileExtension = extname(filePath).toLowerCase();
    const mimeType = contentType(fileExtension) || 'application/octet-stream';

    formData.append('filename', new File([file.readable as any], filename, { type: mimeType, lastModified: fileInfo.mtime?.getTime() || Date.now() }));

    // 发送请求
    const response = await fetch(uploadUrl, {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const result = await response.text();
    console.log('上传成功:', result);
    file.close();
  } catch (error) {
    console.error('上传失败:', error);
  }
}

Deno.test('upload vuln file', async () => {
  // 使用示例
  const filePath = resolve(import.meta.dirname as string, 'test.png');
  console.log(filePath);
  const uploadUrl = 'http://localhost:8787/upload/case/nullbyte';
  await uploadFile(filePath, uploadUrl);
});

Deno.test('test file-upload nullcheck', async () => {
  await testFileuploadPlugin();
});
async function testFileuploadPlugin() {
  const filePath = resolve(import.meta.dirname as string, 'test.png');
  console.log(filePath);
  const uploadUrl = 'http://localhost:8787/upload/case/nullbyte';
  const file = await Deno.open(filePath);
  const fileInfo = await file.stat();
  // 创建FormData对象
  const formData = new FormData();
  let filename = basename(filePath);
  const fileExtension = extname(filePath).toLowerCase();
  const mimeType = contentType(fileExtension) || 'application/octet-stream';

  formData.append('filename', new File([file.readable as any], filename, { type: mimeType, lastModified: fileInfo.mtime?.getTime() || Date.now() }));

  // 发送请求
  const request = new Request(uploadUrl, {
    method: 'POST',
    body: formData,
  });
  await endpoint(request);
}

Deno.test('mimetype bypass', async () => {
  await mimeTypeByPassTest();
});
async function mimeTypeByPassTest() {
  const filePath = resolve(import.meta.dirname as string, 'test.png');
  console.log(filePath);
  const uploadUrl = 'http://localhost:8787/upload/case/mime';
  const file = await Deno.open(filePath);
  const fileInfo = await file.stat();
  // 创建FormData对象
  const formData = new FormData();
  let filename = basename(filePath);
  const fileExtension = extname(filePath).toLowerCase();
  const mimeType = contentType(fileExtension) || 'application/octet-stream';

  formData.append('filename', new File([file.readable as any], filename, { type: mimeType, lastModified: fileInfo.mtime?.getTime() || Date.now() }));
  // 发送请求
  const request = new Request(uploadUrl, {
    method: 'POST',
    body: formData,
  });
  await endpoint(request);
}

await mimeTypeByPassTest();

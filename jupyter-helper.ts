/// <refrerence types=>
// import {Table} from 'npm:tabulator-tables'


export type TTable<T> = {
    id?: string;
    data:T[],
    columns:{
      title:string,
      field:string,
      hozAlign?:string,
      formatter?:string,
      sorter?:string,
      width?:number,
    }[],
    height?:number,
    layout?:string|'fitColumns',
    movableRows?:boolean,
  }
export function tabulator<T>(tableOptions: TTable<T>): number {
    let id = tableOptions.id || "a"+ crypto.randomUUID();
    return `<html style="min-height:300px">
  
    <link href="https://esm.sh/tabulator-tables@6.3.1/dist/css/tabulator_midnight.css" rel="stylesheet">
    
    
    <div id="${id}"></div>
    <script type="module"> 
    import {Tabulator,SortModule} from 'https://esm.sh/tabulator-tables@6.3.1/dist/js/tabulator_esm.min.mjs';
    Tabulator.registerModule([SortModule]);
   
    var table = new Tabulator("#${id}", ${JSON.stringify(tableOptions)})
    
    </script>
    
    </html>`
  }
  


  // FILEPATH: traffic_detail.ts

export interface TrafficData {
  request: {
    url: string;
    method: string;
    body: string;
  };
  response: {
    status_code: number;
    body: string;
  };
}

export function generateTrafficDetailHtml(trafficData: TrafficData): string {
  return `
<html lang="en" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Traffic Detail</title>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@3.1.0/dist/full.css" rel="stylesheet" type="text/css" />
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body>
    <div class="container mx-auto p-4">
        <h1 class="text-2xl font-bold mb-4">Traffic Detail</h1>
        <div class="card bg-base-100 shadow-xl">
            <div class="card-body">
                <h2 class="card-title">Request</h2>
                <div class="overflow-x-auto">
                    <table class="table w-full">
                        <tbody>
                            <tr>
                                <td class="font-bold">URL</td>
                                <td>${trafficData.request.url}</td>
                            </tr>
                            <tr>
                                <td class="font-bold">Method</td>
                                <td>${trafficData.request.method}</td>
                            </tr>
                            <tr>
                                <td class="font-bold">Request Body</td>
                                <td>
                                    <pre class="bg-base-200 p-2 rounded"><code>${trafficData.request?.body}</code></pre>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                
                <h2 class="card-title mt-4">Response</h2>
                <div class="overflow-x-auto">
                    <table class="table w-full">
                        <tbody>
                            <tr>
                                <td class="font-bold">Status Code</td>
                                <td>${trafficData.response?.status_code}</td>
                            </tr>
                            <tr>
                                <td class="font-bold">Response Body</td>
                                <td>
                                    <pre class="bg-base-200 p-2 rounded"></pre>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
  `;
}

export function tabulatorAuto<T>(tableOptions: TTable<T>): string {
    let allColumns = [];
    tableOptions.data.forEach(item => {
        let keys = Object.keys(item);
        for (let k of keys) {
            if(!allColumns.find(c=>c.field===k)){
                allColumns.push({
                    field: k,
                    sorter: tableOptions.data.map(i => i[k]).some(i => typeof i === 'string') ? 'string' : 'number',
                    title:k
                })
            }       
        }
     
    })
    return tabulator({
        ...tableOptions,
        columns:allColumns
    })
}

// 示例使用
// const trafficData: TrafficData = {
//   request: {
//     url: "https://example.com/api",
//     method: "POST",
//     body: '{"key": "value"}'
//   },
//   response: {
//     status_code: 200,
//     body: '{"result": "success"}'
//   }
// };

// const htmlContent = generateTrafficDetailHtml(trafficData);

// // 将生成的HTML内容写入文件
// await Deno.writeTextFile("traffic_detail.html", htmlContent);

// console.log("HTML file has been generated: traffic_detail.html");
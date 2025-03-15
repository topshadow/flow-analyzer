export async function surrealDbFetch(
  query: string,
  vars: Record<string, any> = {},
): Promise<any> {
  const url = `http://localhost:8000/sql`; // 替换为您的SurrealDB地址
    const headers = {
        'Accept': 'application/json',

    "surreal-ns": "test", // 替换为您的命名空间
    "surreal-db": "test", // 替换为您的数据库名
    "Authorization": "Basic " + btoa("root:root"), // 替换为您的凭证
  };

  const body = JSON.stringify({ query, vars });

  try {
    const response = await fetch(url, {
      method: "POST",
      headers,
      body:query,
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    return data;
  } catch (error) {
    console.error("Error:", error);
    throw error;
  }
}

Deno.test("test query", async () => {
  let res = await surrealDbFetch("select * from httpx", {});
  console.log(res);
});
// 使用示例:
// 创建记录
// surrealDbFetch('create', 'POST', 'CREATE person SET name = $name', { name: 'John Doe' });

// 读取记录
// surrealDbFetch('select', 'GET', 'SELECT * FROM person');

// 更新记录
// surrealDbFetch('update', 'PATCH', 'UPDATE person:john SET age = $age', { age: 30 });

// 删除记录
// surrealDbFetch('delete', 'DELETE', 'DELETE FROM person WHERE id = $id', { id: 'john' });

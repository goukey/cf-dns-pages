// 处理OPTIONS请求，支持CORS预检
export function onRequest(context) {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Accept, X-Requested-With',
      'Access-Control-Max-Age': '86400',
      'Cache-Control': 'no-cache',
    },
  });
} 
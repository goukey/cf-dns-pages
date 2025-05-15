export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);
  
  // 获取查询参数
  const domain = url.searchParams.get('name') || 'example.com';
  const type = url.searchParams.get('type') || 'A';
  
  // 构建Cloudflare DNS-over-HTTPS请求
  const dnsUrl = new URL('https://cloudflare-dns.com/dns-query');
  dnsUrl.searchParams.set('name', domain);
  dnsUrl.searchParams.set('type', type);
  
  try {
    // 发送请求到Cloudflare DNS
    const dnsResponse = await fetch(dnsUrl, {
      headers: {
        'Accept': 'application/dns-json'
      }
    });
    
    // 获取响应数据
    const dnsData = await dnsResponse.json();
    
    // 返回结果
    return new Response(JSON.stringify({
      success: true,
      query: {
        domain,
        type
      },
      dnsUrl: dnsUrl.toString(),
      result: dnsData
    }), {
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  } catch (error) {
    // 如果出错，返回错误信息
    return new Response(JSON.stringify({
      success: false,
      error: error.message,
      query: {
        domain,
        type
      },
      dnsUrl: dnsUrl.toString()
    }), {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
} 
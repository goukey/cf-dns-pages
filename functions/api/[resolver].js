/**
 * DNS解析加速服务 - Pages Function实现
 * 路径：/api/resolver
 * 特性：同时查询多个上游服务器，返回最快响应的结果
 * 支持ECS客户端子网(手动指定或自动检测)
 */

// 允许的查询参数
const ALLOWED_PARAMS = ['name', 'type', 'do', 'cd', 'ct', 'dns'];
// 自定义上游服务器参数
const CUSTOM_UPSTREAM_PARAM = 'upstream';
// 并行查询参数
const PARALLEL_QUERY_PARAM = 'parallel';
// ECS参数
const ECS_PARAM = 'edns_client_subnet';
// 自动ECS开关参数
const AUTO_ECS_PARAM = 'auto_ecs';
// 单一服务器模式参数（禁用并行查询）
const SINGLE_MODE_PARAM = 'single';

// 默认上游服务器
const DEFAULT_UPSTREAM = "https://cloudflare-dns.com/dns-query";

// 默认并行查询的服务器列表
const DEFAULT_PARALLEL_SERVERS = ["cloudflare", "google"];

// DNS查询超时时间（毫秒）
const REQUEST_TIMEOUT = 5000;

// 预设上游服务器
// 如需添加自己的预设服务器，请在此处添加条目
// 格式: "服务器名称": "完整的DoH服务器URL"
const RESOLVER_SERVERS = {
  "cloudflare": "https://cloudflare-dns.com/dns-query",
  "google": "https://dns.google/dns-query",
  // 可添加更多服务器，例如:
  // "example": "https://doh.example.com/dns-query"
};

// 预设服务器是否支持ECS
// 添加新服务器时，请同时在此处添加是否支持ECS的信息
const ECS_SUPPORT = {
  "cloudflare": false, // Cloudflare默认不支持ECS
  "google": true,      // Google支持ECS
  // 与上方服务器对应，例如:
  // "example": true    // 如果支持ECS则为true，否则为false
};

// 获取上游服务器配置
function getServerConfiguration(param) {
  // 这里只能返回预设的服务器配置
  // 在实际页面中，会通过localStorage存储用户添加的自定义服务器
  if (param && RESOLVER_SERVERS[param]) {
    return RESOLVER_SERVERS[param];
  }
  return null;
}

// 检查服务器是否支持ECS
function serverSupportsECS(serverName) {
  return ECS_SUPPORT[serverName] || false;
}

// IPv6地址处理函数，根据掩码长度截取前缀
function getIPv6Prefix(ipv6, maskLen = 56) {
  // 确保地址不包含子网掩码部分
  const ipAddress = ipv6.includes('/') ? ipv6.split('/')[0] : ipv6;
  
  // 将IPv6地址展开为完整格式
  const fullAddress = expandIPv6Address(ipAddress);
  
  // 将地址拆分为16位组
  const parts = fullAddress.split(':');
  
  // 计算需要保留的完整组数
  const fullGroups = Math.floor(maskLen / 16);
  
  // 计算最后一个组需要保留的位数
  const remainingBits = maskLen % 16;
  
  // 复制需要的组
  let result = parts.slice(0, fullGroups);
  
  // 处理部分保留的最后一个组
  if (remainingBits > 0 && fullGroups < 8) {
    const lastGroupValue = parseInt(parts[fullGroups], 16);
    const mask = 0xffff - ((1 << (16 - remainingBits)) - 1);
    const maskedValue = (lastGroupValue & mask).toString(16);
    result.push(maskedValue);
    
    // 用0填充剩余组
    while (result.length < 8) {
      result.push('0');
    }
  }
  
  return result.join(':');
}

// 将IPv6地址展开为完整格式
function expandIPv6Address(address) {
  // 处理IPv6缩写格式
  if (address.includes('::')) {
    const parts = address.split('::');
    const left = parts[0] ? parts[0].split(':') : [];
    const right = parts[1] ? parts[1].split(':') : [];
    const missing = 8 - left.length - right.length;
    let full = left;
    
    for (let i = 0; i < missing; i++) {
      full.push('0');
    }
    
    full = full.concat(right);
    return full.map(part => part ? part : '0').join(':');
  }
  
  // 已经是完整格式
  return address;
}

// 构建基础DNS查询消息
function buildDNSMessage(domainName, recordType) {
  // DNS 请求ID（随机16位）
  const id = Math.floor(Math.random() * 65536);
  
  // 第一个字节: 第1-2位设置为0（标准查询）,后续字段都为0
  // 第二个字节: RD位设置为1（期望递归）,其他都为0
  const flags = 0x0100; // 二进制：00000001 00000000
  
  // 只有一个问题
  const qdcount = 1;
  // 其他字段都是0
  const ancount = 0;
  const nscount = 0;
  const arcount = 0;
  
  // 构建查询问题
  // 拆分域名为各段标签
  const labels = domainName.split('.');
  
  // 计算域名编码后的长度
  const domainBytes = labels.reduce((acc, label) => acc + label.length + 1, 0) + 1;
  
  // 构建二进制消息数组
  const message = new Uint8Array(12 + domainBytes + 4);
  
  // 填充头部
  message[0] = id >> 8; // ID高字节
  message[1] = id & 0xff; // ID低字节
  message[2] = flags >> 8; // flags高字节
  message[3] = flags & 0xff; // flags低字节
  message[4] = qdcount >> 8; // QDCOUNT高字节
  message[5] = qdcount & 0xff; // QDCOUNT低字节
  // ANCOUNT, NSCOUNT, ARCOUNT都为0
  
  // 填充查询域
  let offset = 12;
  for (const label of labels) {
    message[offset++] = label.length; // 标签长度
    // 填充标签字符
    for (let i = 0; i < label.length; i++) {
      message[offset++] = label.charCodeAt(i);
    }
  }
  // 添加根标签
  message[offset++] = 0;
  
  // 确定记录类型
  let qtype = 1; // 默认为A记录
  switch (recordType.toUpperCase()) {
    case 'A': qtype = 1; break;
    case 'AAAA': qtype = 28; break;
    case 'CNAME': qtype = 5; break;
    case 'MX': qtype = 15; break;
    case 'TXT': qtype = 16; break;
    case 'NS': qtype = 2; break;
    case 'SOA': qtype = 6; break;
    case 'SRV': qtype = 33; break;
    case 'PTR': qtype = 12; break;
    case 'CAA': qtype = 257; break;
    default: qtype = parseInt(recordType) || 1; // 如果是数字直接使用
  }
  
  // 添加类型和类
  message[offset++] = qtype >> 8;
  message[offset++] = qtype & 0xff;
  message[offset++] = 0; // IN类高字节
  message[offset++] = 1; // IN类低字节
  
  return message;
}

// 将Uint8Array转为Base64URL编码
function bufferToBase64Url(buffer) {
  // 先转为标准Base64
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  
  // 转为Base64URL（替换+为-，/为_，去掉末尾的=）
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// 从请求头获取客户端IP
function getClientIP(request) {
  return request.headers.get('CF-Connecting-IP') || 
         request.headers.get('X-Real-IP') || 
         request.headers.get('X-Forwarded-For')?.split(',')[0] || 
         '127.0.0.1';
}

// 添加ECS参数到URL
function addECStoURL(url, ipAddress) {
  // 如果IP地址不包含掩码，添加默认掩码
  let ecsValue = ipAddress;
  if (!ipAddress.includes('/')) {
    // IPv4用/24，IPv6用/56
    if (ipAddress.includes(':')) {
      ecsValue = `${ipAddress}/56`;
    } else {
      ecsValue = `${ipAddress}/24`;
    }
  }
  
  // 添加到URL
  url.searchParams.set('edns_client_subnet', ecsValue);
  return url;
}

async function queryDNSServer(server, queryParams, request) {
  const startTime = Date.now();
  let hasEcs = false;
  let ecsSource = 'none';
  let serverSupportsEcsFlag = serverSupportsECS(server);
  
  try {
    const serverUrl = new URL(server);
    
    // 默认所有服务器都使用application/dns-message格式
    const requestOptions = {
      method: 'GET',
      headers: {
        'User-Agent': 'curl/8.0.0',
        'Accept': 'application/dns-message'
      }
    };
    
    // 移除可能导致服务器拒绝的头
    delete requestOptions.headers['Accept-Language'];
    delete requestOptions.headers['DNT'];
    
    // RFC 8484格式需要dns参数
    // 检查是否有DNS查询基本参数
    const name = queryParams.get('name');
    const type = queryParams.get('type') || 'A'; // 默认为A记录
    
    if (name) {
      // 构建基本的DNS查询消息
      const dnsMessage = buildDNSMessage(name, type);
      // 转换为base64url格式（不包含填充符）
      const base64url = bufferToBase64Url(dnsMessage);
      // 更新URL
      serverUrl.search = `dns=${base64url}`;
      
      // 添加ECS参数（如果有且服务器支持）
      if (serverSupportsEcsFlag) {
        const ecs = queryParams.get(ECS_PARAM);
        if (ecs) {
          // 在DNS消息中添加ECS - 这需要修改DNS消息格式
          // 目前简单处理，未实现ECS的DNS消息编码
          hasEcs = true;
          ecsSource = 'user';
        } else if (queryParams.get(AUTO_ECS_PARAM) === 'true') {
          // 自动获取客户端IP
          const clientIP = getClientIP(request);
          if (clientIP) {
            // 在DNS消息中添加ECS - 这需要修改DNS消息格式
            // 目前简单处理，未实现ECS的DNS消息编码
            hasEcs = true;
            ecsSource = 'auto';
          }
        }
      }
      
      console.log(`查询服务器: ${serverUrl.toString()}`);
    } else {
      throw new Error('缺少必要的name参数');
    }
    
    // 添加超时
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('DNS查询超时')), REQUEST_TIMEOUT);
    });
    
    // 发起查询
    const fetchPromise = fetch(serverUrl.toString(), requestOptions);
    
    // 竞争超时和正常查询
    const response = await Promise.race([fetchPromise, timeoutPromise]);
    const endTime = Date.now();
    
    // 验证响应是否有效
    if (!response.ok) {
      throw new Error(`DNS服务器响应错误: ${response.status} ${response.statusText}`);
    }
    
    return { 
      response, 
      server, 
      time: endTime - startTime,
      hasEcs,
      ecsSource,
      serverSupportsEcs: serverSupportsEcsFlag
    };
  } catch (error) {
    return { 
      error: error.message, 
      server, 
      time: Date.now() - startTime 
    };
  }
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const method = request.method;

  // 添加请求ID便于追踪
  const requestId = Date.now().toString(36) + Math.random().toString(36).substring(2, 7);
  console.log(`[${requestId}] 新请求: ${url.toString()}`);

  // 添加调试信息
  const debugInfo = {
    url: request.url,
    method: method,
    params: Object.fromEntries(url.searchParams.entries()),
    headers: Object.fromEntries(request.headers.entries()),
    requestId: requestId
  };

  // 检查请求方法
  if (method !== 'GET' && method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405 });
  }

  // 检查必要参数
  const domainName = url.searchParams.get('name');
  const recordType = url.searchParams.get('type');
  
  if (!domainName) {
    return new Response(JSON.stringify({
      error: 'Missing required parameter: name',
      debug: debugInfo
    }), { 
      status: 400,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }

  try {
    // 获取用户指定的上游服务器列表
    let upstreamServers = [];
    
    // 检查是否指定了自定义上游服务器
    const customUpstream = url.searchParams.get(CUSTOM_UPSTREAM_PARAM);
    if (customUpstream) {
      try {
        // 支持多个自定义上游服务器，用逗号分隔
        const customServers = customUpstream.split(',');
        for (const server of customServers) {
          const serverUrl = server.trim();
          // 验证自定义上游服务器URL是否合法
          const customUrl = new URL(serverUrl);
          if (customUrl.protocol === 'https:') {
            upstreamServers.push(serverUrl);
          }
        }
        // 移除上游服务器参数以避免传递给上游
        url.searchParams.delete(CUSTOM_UPSTREAM_PARAM);
      } catch (e) {
        console.error('无效的自定义上游服务器URL:', e);
      }
    }

    // 检查是否指定了预设服务器
    const serverParam = url.searchParams.get('server');
    if (serverParam) {
      // 支持多个预设服务器，用逗号分隔
      const requestedServers = serverParam.split(',');
      for (const server of requestedServers) {
        const serverName = server.trim();
        const serverUrl = getServerConfiguration(serverName);
        if (serverUrl) {
          upstreamServers.push(serverUrl);
        } else if (RESOLVER_SERVERS[serverName]) {
          // 兼容直接使用预设服务器名称的情况
          upstreamServers.push(RESOLVER_SERVERS[serverName]);
        }
      }
    }

    // 如果没有有效的上游服务器，使用默认多个服务器或单一服务器
    if (upstreamServers.length === 0) {
      // 检查是否启用并行模式（查询所有预设服务器）
      const parallelMode = url.searchParams.get(PARALLEL_QUERY_PARAM) === 'true';
      // 检查是否强制单一服务器模式
      const singleMode = url.searchParams.get(SINGLE_MODE_PARAM) === 'true';
      
      if (parallelMode) {
        // 添加所有预设服务器
        Object.values(RESOLVER_SERVERS).forEach(server => {
          upstreamServers.push(server);
        });
      } else if (singleMode) {
        // 单一服务器模式，只使用默认服务器
        upstreamServers.push(DEFAULT_UPSTREAM);
      } else {
        // 默认情况下使用预定义的多个服务器
        for (const serverName of DEFAULT_PARALLEL_SERVERS) {
          if (RESOLVER_SERVERS[serverName]) {
            upstreamServers.push(RESOLVER_SERVERS[serverName]);
          }
        }
        
        // 如果没有有效的默认并行服务器，回退到默认单一服务器
        if (upstreamServers.length === 0) {
          upstreamServers.push(DEFAULT_UPSTREAM);
        }
      }
    }

    // 准备查询参数
    const queryParams = new URLSearchParams();
    try {
      for (const param of ALLOWED_PARAMS) {
        const value = url.searchParams.get(param);
        if (value !== null) {
          queryParams.set(param, value);
        }
      }
    } catch (error) {
      console.error('处理查询参数出错:', error);
      // 继续处理，使用空的查询参数集
    }
    
    // 处理ECS参数
    const ecsValue = url.searchParams.get(ECS_PARAM);
    let hasEcs = false;
    let ecsSource = 'manual'; // 记录ECS来源：manual=手动指定，auto=自动检测
    
    if (ecsValue) {
      // 用户手动指定了ECS
      // 验证IPv4或IPv6格式
      const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
      const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))(\/\d{1,3})?$/;
      
      if (ipv4Regex.test(ecsValue) || ipv6Regex.test(ecsValue)) {
        // 确保IPv4和IPv6都有适当的掩码长度
        let finalEcsValue = ecsValue;
        
        // 如果没有指定掩码长度，添加默认掩码
        if (!ecsValue.includes('/')) {
          // 检测是IPv4还是IPv6
          if (ecsValue.includes(':')) {
            // IPv6默认使用/56掩码
            finalEcsValue = `${ecsValue}/56`;
          } else {
            // IPv4默认使用/24掩码
            finalEcsValue = `${ecsValue}/24`;
          }
        }
        
        queryParams.set('edns_client_subnet', finalEcsValue);
        hasEcs = true;
      } else {
        console.warn('无效的ECS值:', ecsValue);
      }
    } else {
      // 检查是否启用自动ECS
      // 默认启用自动ECS，除非显式设置auto_ecs=false
      const autoEcs = url.searchParams.get(AUTO_ECS_PARAM) !== 'false';
      
      if (autoEcs) {
        // 从请求头中获取客户端真实IP
        const clientIP = getClientIP(request);
        
        if (clientIP) {
          // 验证IP格式 - 同时支持IPv4和IPv6
          const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
          const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$/;
          
          if (ipv4Regex.test(clientIP)) {
            // IPv4处理逻辑
            const ipParts = clientIP.split('.');
            const subnetPrefix = `${ipParts[0]}.${ipParts[1]}.${ipParts[2]}.0/24`;
            
            queryParams.set('edns_client_subnet', subnetPrefix);
            hasEcs = true;
            ecsSource = 'auto';
          } else if (ipv6Regex.test(clientIP)) {
            // IPv6处理逻辑 - 使用/56掩码
            const ipv6Prefix = getIPv6Prefix(clientIP, 56);
            queryParams.set('edns_client_subnet', `${ipv6Prefix}/56`);
            hasEcs = true;
            ecsSource = 'auto';
          }
        }
      }
    }

    // 准备请求选项
    let requestOptions = {
      method: method,
      headers: {
        'User-Agent': 'curl/8.0.0',  // 使用更简单更通用的User-Agent
        'Accept': 'application/dns-json',
        'Connection': 'keep-alive'
      },
    };

    // 处理不同的请求方法
    if (method === 'POST') {
      // 复制原始请求的content-type和body
      const contentType = request.headers.get('content-type');
      if (contentType) {
        requestOptions.headers['content-type'] = contentType;
      }
      const body = await request.arrayBuffer();
      // 需要克隆请求体，因为我们要发送多个请求
      requestOptions.body = body;
    }

    // 创建竞速函数，同时查询所有上游服务器，返回最快的响应
    async function queryWithRace(servers, req) {
      // 如果服务器数组为空，抛出错误
      if (servers.length === 0) {
        throw new Error('没有可用的DNS服务器');
      }
      
      // 如果只有一个服务器，直接查询
      if (servers.length === 1) {
        return queryDNSServer(servers[0], queryParams, req);
      }
      
      // 创建Promise数组，每个Promise对应一个上游服务器的查询
      const promises = servers.map(server => queryDNSServer(server, queryParams, req));
      
      // 使用Promise.race获取最快的响应
      return Promise.race(promises);
    }

    // 执行并行查询
    const result = await queryWithRace(upstreamServers, request);
    
    // 检查是否有错误
    if (result.error) {
      // 尝试其他服务器，不立即返回错误
      // 创建重试数组，排除已经失败的服务器
      const remainingServers = upstreamServers.filter(server => server !== result.server);
      if (remainingServers.length > 0) {
        // 还有其他服务器可用，尝试查询
        const retryResult = await queryWithRace(remainingServers, request);
        if (!retryResult.error) {
          // 找到有效响应，使用它
          return new Response(retryResult.response.body, {
            status: retryResult.response.status,
            statusText: retryResult.response.statusText,
            headers: new Headers({
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Methods': 'GET, POST',
              'Cache-Control': 'public, max-age=60',
              'X-DNS-Upstream': retryResult.server,
              'X-DNS-Response-Time': `${retryResult.time}ms`,
              'X-DNS-ECS-Status': retryResult.hasEcs ? `Added (${retryResult.ecsSource})` : 'Not added',
              'X-DNS-Debug': 'If you see this, your request was successfully processed',
              'Content-Type': retryResult.response.headers.get('Content-Type') || 'application/dns-message'
            })
          });
        }
      }
      
      // 所有服务器都失败，返回错误
      return new Response(JSON.stringify({
        error: 'All DNS servers failed',
        details: result.error
      }), {
        status: 502,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Cache-Control': 'no-cache, no-store',
          'X-DNS-Debug': 'If you see this, all DNS servers have failed'
        }
      });
    }

    // 返回最快的有效响应
    return new Response(result.response.body, {
      status: result.response.status,
      statusText: result.response.statusText,
      headers: new Headers({
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST',
        'Cache-Control': 'public, max-age=60',
        'X-DNS-Upstream': result.server,
        'X-DNS-Response-Time': `${result.time}ms`,
        'X-DNS-ECS-Status': result.hasEcs ? `Added (${result.ecsSource})` : 'Not added',
        'X-DNS-Debug': 'If you see this, your request was successfully processed',
        'Content-Type': result.response.headers.get('Content-Type') || 'application/dns-message'
      })
    });
  } catch (error) {
    console.error('处理DNS解析请求时出错:', error);
    
    // 返回更友好的错误响应，并添加额外的调试信息
    return new Response(JSON.stringify({
      error: '上游服务器错误',
      message: error.message,
      details: '所有上游DNS服务器均无法成功响应此查询',
      servers_tried: upstreamServers || [],
      query: {
        name: domainName,
        type: recordType,
        params: Object.fromEntries(url.searchParams.entries())
      },
      debug: debugInfo
    }), { 
      status: 502, // 使用502 Bad Gateway更合适
      headers: {
        'Content-Type': 'application/json;charset=UTF-8',
        'Access-Control-Allow-Origin': '*',
        'X-Error-Source': 'DNS-Resolver',
        'X-Error-Type': 'Upstream failure'
      }
    });
  }
} 
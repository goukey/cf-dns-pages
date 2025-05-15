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

// 预设上游服务器
// 如需添加自己的预设服务器，请在此处添加条目
// 格式: "服务器名称": "完整的DoH服务器URL"
const RESOLVER_SERVERS = {
  "cloudflare": "https://cloudflare-dns.com/dns-query",
  "google": "https://dns.google/dns-query",
  "quad9": "https://dns.quad9.net/dns-query",
  "aliyun": "https://dns.alidns.com/dns-query",
  // 可添加更多服务器，例如:
  // "example": "https://doh.example.com/dns-query"
};

// 预设服务器是否支持ECS
// 添加新服务器时，请同时在此处添加是否支持ECS的信息
const ECS_SUPPORT = {
  "cloudflare": false, // Cloudflare默认不支持ECS
  "google": true,      // Google支持ECS
  "quad9": true,       // Quad9支持ECS
  "aliyun": true,      // 阿里云支持ECS
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

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const method = request.method;

  // 添加调试信息
  const debugInfo = {
    url: request.url,
    method: method,
    params: Object.fromEntries(url.searchParams.entries()),
    headers: Object.fromEntries(request.headers.entries())
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
    for (const param of ALLOWED_PARAMS) {
      const value = url.searchParams.get(param);
      if (value !== null) {
        queryParams.set(param, value);
      }
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
        const clientIP = request.headers.get('CF-Connecting-IP') || 
                         request.headers.get('X-Real-IP') || 
                         request.headers.get('X-Forwarded-For')?.split(',')[0];
        
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
        'User-Agent': 'DNS-Resolver/1.0',
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
    async function queryWithRace(servers) {
      // 记录开始时间，用于添加响应时间信息
      const startTime = Date.now();
      
      // 如果只有一个服务器，直接查询不需要竞争
      if (servers.length === 1) {
        const serverUrl = new URL('/dns-query', new URL(servers[0]).origin);
        serverUrl.search = queryParams.toString();
        
        // 对于不支持ECS的服务器，移除ECS参数
        let serverSupportsEcsFlag = true;
        if (hasEcs) {
          // 尝试查找服务器在预设列表中的名称
          const serverName = Object.keys(RESOLVER_SERVERS).find(
            key => RESOLVER_SERVERS[key] === servers[0]
          );
          
          if (serverName && !serverSupportsECS(serverName)) {
            const nonEcsParams = new URLSearchParams(queryParams);
            nonEcsParams.delete('edns_client_subnet');
            serverUrl.search = nonEcsParams.toString();
            serverSupportsEcsFlag = false;
          }
        }
        
        const response = await fetch(serverUrl.toString(), requestOptions);
        const endTime = Date.now();
        return { 
          response, 
          server: servers[0], 
          time: endTime - startTime,
          hasEcs,
          ecsSource,
          serverSupportsEcs: serverSupportsEcsFlag
        };
      }
      
      // 创建Promise数组，每个Promise对应一个上游服务器的查询
      const promises = servers.map(async (server) => {
        const serverUrl = new URL('/dns-query', new URL(server).origin);
        
        // 处理ECS参数，对于不支持ECS的服务器移除ECS参数
        let serverSupportsEcsFlag = true;
        if (hasEcs) {
          // 尝试查找服务器在预设列表中的名称
          const serverName = Object.keys(RESOLVER_SERVERS).find(
            key => RESOLVER_SERVERS[key] === server
          );
          
          if (serverName && !serverSupportsECS(serverName)) {
            const nonEcsParams = new URLSearchParams(queryParams);
            nonEcsParams.delete('edns_client_subnet');
            serverUrl.search = nonEcsParams.toString();
            serverSupportsEcsFlag = false;
          } else {
            serverUrl.search = queryParams.toString();
          }
        } else {
          serverUrl.search = queryParams.toString();
        }
        
        // 使用clone避免body已被读取的问题
        const options = { ...requestOptions };
        if (method === 'POST' && options.body) {
          options.body = options.body.slice(0);
        }
        
        try {
          const response = await fetch(serverUrl.toString(), options);
          const endTime = Date.now();
          return { 
            response, 
            server, 
            time: endTime - startTime,
            hasEcs,
            ecsSource,
            serverSupportsEcs: serverSupportsEcsFlag
          };
        } catch (error) {
          console.error(`查询${server}失败:`, error);
          // 返回一个错误响应，但不中断竞争
          return { 
            error: true, 
            server, 
            time: Date.now() - startTime,
            message: error.message 
          };
        }
      });
      
      // 使用Promise.race等待最快的响应
      return Promise.race(promises);
    }

    // 执行并行查询
    const result = await queryWithRace(upstreamServers);
    
    // 检查是否有错误
    if (result.error) {
      // 尝试其他服务器，不立即返回错误
      // 创建重试数组，排除已经失败的服务器
      const remainingServers = upstreamServers.filter(server => server !== result.server);
      if (remainingServers.length > 0) {
        // 还有其他服务器可用，尝试查询
        const retryResult = await queryWithRace(remainingServers);
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
              'X-DNS-Retried': 'true',
              ...(retryResult.hasEcs ? {
                'X-EDNS-Client-Subnet': queryParams.get('edns_client_subnet'),
                'X-EDNS-Client-Subnet-Used': retryResult.serverSupportsEcs ? 'true' : 'false',
                'X-EDNS-Client-Subnet-Source': retryResult.ecsSource
              } : {})
            })
          });
        }
      }
      
      // 所有服务器都失败，抛出错误
      throw new Error(`所有上游服务器查询失败，最初错误：${result.message}`);
    }

    // 准备返回的Response对象
    const responseHeaders = new Headers({
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST',
      'Cache-Control': 'public, max-age=60',
      // 添加自定义响应头，包含响应来源和响应时间
      'X-DNS-Upstream': result.server,
      'X-DNS-Response-Time': `${result.time}ms`,
    });
    
    // 如果使用了ECS，添加到响应头
    if (result.hasEcs) {
      const ecsParamValue = queryParams.get('edns_client_subnet');
      responseHeaders.set('X-EDNS-Client-Subnet', ecsParamValue);
      responseHeaders.set('X-EDNS-Client-Subnet-Used', result.serverSupportsEcs ? 'true' : 'false');
      responseHeaders.set('X-EDNS-Client-Subnet-Source', result.ecsSource);
    }

    // 复制响应的内容类型
    const contentType = result.response.headers.get('content-type');
    if (contentType) {
      responseHeaders.set('content-type', contentType);
    }

    // 返回最快上游服务器的响应
    return new Response(result.response.body, {
      status: result.response.status,
      statusText: result.response.statusText,
      headers: responseHeaders,
    });
  } catch (error) {
    console.error('处理DNS解析请求时出错:', error);
    return new Response(JSON.stringify({
      error: '服务器内部错误',
      message: error.message,
      stack: error.stack,
      debug: debugInfo
    }), { 
      status: 500,
      headers: {
        'Content-Type': 'application/json;charset=UTF-8',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
} 
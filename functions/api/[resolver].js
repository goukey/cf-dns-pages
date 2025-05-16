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
// DNS查询结果格式参数
const FORMAT_PARAM = 'format';
// 显示所有类型记录参数
const ALL_TYPES_PARAM = 'all_types';

// 默认上游服务器
const DEFAULT_UPSTREAM = "https://cloudflare-dns.com/dns-query";

// 默认并行查询的服务器列表
const DEFAULT_PARALLEL_SERVERS = ["cloudflare", "google"];

// DNS查询超时时间（毫秒）
const REQUEST_TIMEOUT = 5000;

// 增加重试配置
const RETRY_CONFIG = {
  maxRetries: 2,           // 最大重试次数
  initialBackoff: 200,     // 初始重试间隔（毫秒）
  backoffMultiplier: 1.5   // 重试间隔乘数
};

// 预设上游服务器
// 如需添加自己的预设服务器，请在此处添加条目
// 格式: "服务器名称": "完整的DoH服务器URL"
const RESOLVER_SERVERS = {
  "cloudflare": "https://cloudflare-dns.com/dns-query",
  "google": "https://dns.google/dns-query",
  "aliyun": "https://dns.alidns.com/dns-query",
  "dnspod": "https://doh.pub/dns-query",
  "adguard": "https://dns.adguard.com/dns-query"
};

// 预设服务器是否支持ECS
// 添加新服务器时，请同时在此处添加是否支持ECS的信息
const ECS_SUPPORT = {
  "cloudflare": false, // Cloudflare默认不支持ECS
  "google": true,      // Google支持ECS
  "aliyun": true,      // 阿里云DNS支持ECS
  "dnspod": true,      // DNSPod支持ECS
  "adguard": true      // AdGuard DNS支持ECS
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
  let qtype = 255; // 默认为ANY记录，查询所有类型
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
    case 'ANY': qtype = 255; break; // ANY查询所有记录类型
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
    
    // 统一使用RFC 8484标准格式 - application/dns-message
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
    // 如果没有指定类型，使用特殊的ANY类型(255)查询所有记录类型
    // 注意：部分DNS服务器可能不支持ANY查询
    const type = queryParams.get('type') || 'ANY';
    
    if (name) {
      // 构建基本的DNS查询消息 - 保留原始类型，包括ANY
      const dnsMessage = buildDNSMessage(name, type);
      // 转换为base64url格式（不包含填充符）
      const base64url = bufferToBase64Url(dnsMessage);
      // 更新URL
      serverUrl.search = `dns=${base64url}`;
      
      // 添加ECS参数（如果有且服务器支持）
      if (serverSupportsEcsFlag) {
        const ecs = queryParams.get(ECS_PARAM);
        if (ecs) {
          hasEcs = true;
          ecsSource = 'user';
          // 由于我们使用dns参数传递base64编码的DNS查询消息，
          // ECS需要在DNS消息中编码，这里暂不实现
          // 如果需要，请在buildDNSMessage函数中添加ECS支持
        } else if (queryParams.get(AUTO_ECS_PARAM) === 'true') {
          // 自动获取客户端IP
          const clientIP = getClientIP(request);
          if (clientIP) {
            hasEcs = true;
            ecsSource = 'auto';
            // 同上，实际ECS编码需要修改DNS消息
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

// 从DNS响应中提取IP地址
function extractIPsFromDNSResponse(buffer, recordType = 'ANY') {
  try {
    // 创建数据视图
    const view = new DataView(buffer);
    
    // 解析DNS头部
    const qdcount = view.getUint16(4); // 问题计数
    const ancount = view.getUint16(6); // 回答计数
    
    if (ancount === 0) {
      return []; // 没有回答记录
    }
    
    // 跳过查询部分
    let offset = 12; // DNS头部长度为12字节
    
    // 跳过所有问题
    for (let i = 0; i < qdcount; i++) {
      // 跳过域名
      while (true) {
        const len = view.getUint8(offset);
        if (len === 0) {
          offset += 1;
          break;
        }
        if ((len & 0xc0) === 0xc0) {
          // 压缩标签
          offset += 2;
          break;
        }
        offset += len + 1;
      }
      
      // 跳过类型和类
      offset += 4;
    }
    
    // 解析回答记录
    const ips = [];
    for (let i = 0; i < ancount; i++) {
      // 跳过域名
      while (true) {
        const len = view.getUint8(offset);
        if (len === 0) {
          offset += 1;
          break;
        }
        if ((len & 0xc0) === 0xc0) {
          // 压缩标签
          offset += 2;
          break;
        }
        offset += len + 1;
      }
      
      // 读取记录类型
      const type = view.getUint16(offset);
      offset += 2;
      
      // 跳过类
      offset += 2;
      
      // 跳过TTL
      offset += 4;
      
      // 读取数据长度
      const rdlength = view.getUint16(offset);
      offset += 2;
      
      // 检查记录类型是否匹配
      const isTypeA = (type === 1 && recordType.toUpperCase() === 'A');
      const isTypeAAAA = (type === 28 && recordType.toUpperCase() === 'AAAA');
      
      if (isTypeA) {
        // A记录（IPv4地址）
        if (rdlength === 4) {
          const ip = `${view.getUint8(offset)}.${view.getUint8(offset+1)}.${view.getUint8(offset+2)}.${view.getUint8(offset+3)}`;
          ips.push(ip);
        }
      } else if (isTypeAAAA) {
        // AAAA记录（IPv6地址）
        if (rdlength === 16) {
          let ip = '';
          for (let j = 0; j < 8; j++) {
            const hexPart = view.getUint16(offset + j * 2).toString(16);
            ip += (j > 0 ? ':' : '') + hexPart;
          }
          ips.push(ip);
        }
      }
      
      // 跳过数据
      offset += rdlength;
    }
    
    return ips;
  } catch (error) {
    console.error('解析DNS响应时出错:', error);
    return [];
  }
}

// 从DNS响应中提取多种类型的记录
function extractAllRecordsFromDNSResponse(buffer) {
  try {
    // 创建数据视图
    const view = new DataView(buffer);
    
    // 解析DNS头部
    const qdcount = view.getUint16(4); // 问题计数
    const ancount = view.getUint16(6); // 回答计数
    
    if (ancount === 0) {
      return {}; // 没有回答记录
    }
    
    // 跳过查询部分
    let offset = 12; // DNS头部长度为12字节
    
    // 跳过所有问题
    for (let i = 0; i < qdcount; i++) {
      // 跳过域名
      while (true) {
        const len = view.getUint8(offset);
        if (len === 0) {
          offset += 1;
          break;
        }
        if ((len & 0xc0) === 0xc0) {
          // 压缩标签
          offset += 2;
          break;
        }
        offset += len + 1;
      }
      
      // 跳过类型和类
      offset += 4;
    }
    
    // 解析回答记录
    const records = {
      A: [],
      AAAA: [],
      CNAME: [],
      MX: [],
      TXT: [],
      NS: [],
      SOA: [],
      SRV: [],
      PTR: [],
      CAA: []
    };
    
    const readDomainName = (startOffset) => {
      let result = '';
      let currentOffset = startOffset;
      let jumping = false;
      let jumpCount = 0;
      
      // 防止无限循环
      const maxJumps = 10;
      
      while (true) {
        if (jumpCount > maxJumps) {
          return { name: '[解析错误:过多的压缩跳转]', offset: currentOffset };
        }
        
        const len = view.getUint8(currentOffset);
        if (len === 0) {
          // 域名结束
          currentOffset += 1;
          break;
        }
        
        if ((len & 0xc0) === 0xc0) {
          // 压缩标签，跳转到指定位置
          if (!jumping) {
            // 只在第一次跳转时移动当前偏移
            jumping = true;
          }
          
          // 计算跳转位置
          const jumpOffset = ((len & 0x3f) << 8) | view.getUint8(currentOffset + 1);
          currentOffset = jumpOffset;
          jumpCount++;
          continue;
        }
        
        // 读取标签
        currentOffset += 1;
        let label = '';
        for (let i = 0; i < len; i++) {
          label += String.fromCharCode(view.getUint8(currentOffset + i));
        }
        result += (result ? '.' : '') + label;
        currentOffset += len;
      }
      
      return { 
        name: result, 
        offset: jumping ? startOffset + 2 : currentOffset // 如果发生了跳转，返回原始位置+2
      };
    };
    
    for (let i = 0; i < ancount; i++) {
      // 读取域名
      const domainResult = readDomainName(offset);
      const domainName = domainResult.name;
      offset = domainResult.offset;
      
      // 读取记录类型
      const type = view.getUint16(offset);
      offset += 2;
      
      // 读取类
      const recordClass = view.getUint16(offset);
      offset += 2;
      
      // 读取TTL
      const ttl = view.getUint32(offset);
      offset += 4;
      
      // 读取数据长度
      const rdlength = view.getUint16(offset);
      offset += 2;
      
      // 根据记录类型解析数据
      switch (type) {
        case 1: // A记录
          if (rdlength === 4) {
            const ip = `${view.getUint8(offset)}.${view.getUint8(offset+1)}.${view.getUint8(offset+2)}.${view.getUint8(offset+3)}`;
            records.A.push({ name: domainName, value: ip, ttl });
          }
          break;
          
        case 28: // AAAA记录
          if (rdlength === 16) {
            let ip = '';
            for (let j = 0; j < 8; j++) {
              const hexPart = view.getUint16(offset + j * 2).toString(16);
              ip += (j > 0 ? ':' : '') + hexPart;
            }
            records.AAAA.push({ name: domainName, value: ip, ttl });
          }
          break;
          
        case 5: // CNAME记录
          {
            const cnameResult = readDomainName(offset);
            records.CNAME.push({ name: domainName, value: cnameResult.name, ttl });
          }
          break;
          
        case 15: // MX记录
          {
            const preference = view.getUint16(offset);
            const exchangeResult = readDomainName(offset + 2);
            records.MX.push({ 
              name: domainName, 
              value: { preference, exchange: exchangeResult.name }, 
              ttl 
            });
          }
          break;
          
        case 16: // TXT记录
          {
            let txtOffset = offset;
            let txtValue = '';
            const txtLength = view.getUint8(txtOffset);
            txtOffset++;
            for (let j = 0; j < txtLength; j++) {
              txtValue += String.fromCharCode(view.getUint8(txtOffset + j));
            }
            records.TXT.push({ name: domainName, value: txtValue, ttl });
          }
          break;
          
        case 2: // NS记录
          {
            const nsResult = readDomainName(offset);
            records.NS.push({ name: domainName, value: nsResult.name, ttl });
          }
          break;
      }
      
      // 跳过数据部分
      offset += rdlength;
    }
    
    // 清理空数组
    Object.keys(records).forEach(key => {
      if (records[key].length === 0) {
        delete records[key];
      }
    });
    
    return records;
  } catch (error) {
    console.error('解析DNS响应时出错:', error);
    return {};
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

    // 添加带重试逻辑的查询函数
    async function queryWithRetry(server, params, req, retryCount = 0) {
      try {
        return await queryDNSServer(server, params, req);
      } catch (error) {
        if (retryCount < RETRY_CONFIG.maxRetries) {
          // 计算退避时间
          const backoffTime = RETRY_CONFIG.initialBackoff * Math.pow(RETRY_CONFIG.backoffMultiplier, retryCount);
          
          // 等待一段时间后重试
          await new Promise(resolve => setTimeout(resolve, backoffTime));
          
          // 记录重试日志
          console.log(`[重试 ${retryCount + 1}/${RETRY_CONFIG.maxRetries}] 重试服务器 ${server}`);
          
          // 递归重试
          return queryWithRetry(server, params, req, retryCount + 1);
        }
        
        // 达到最大重试次数，返回带有重试信息的错误
        return {
          error: error.message,
          server: server,
          retried: retryCount,
          maxRetries: RETRY_CONFIG.maxRetries
        };
      }
    }

    // 创建竞速函数，同时查询所有上游服务器，返回最快的响应
    async function queryWithRace(servers, req) {
      // 如果服务器数组为空，抛出错误
      if (servers.length === 0) {
        throw new Error('没有可用的DNS服务器');
      }
      
      // 如果只有一个服务器，使用带重试的查询
      if (servers.length === 1) {
        return queryWithRetry(servers[0], queryParams, req);
      }
      
      // 创建Promise数组，每个Promise对应一个上游服务器的查询
      const promises = servers.map(server => queryWithRetry(server, queryParams, req));
      
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
          const responseHeaders = new Headers({
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST',
            'Cache-Control': 'public, max-age=60',
            'X-DNS-Upstream': retryResult.server,
            'X-DNS-Response-Time': `${retryResult.time}ms`,
            'X-DNS-ECS-Status': retryResult.hasEcs ? `Added (${retryResult.ecsSource})` : 'Not added',
            'X-DNS-Debug': 'If you see this, your request was successfully processed',
            'Content-Type': retryResult.response.headers.get('Content-Type') || 'application/dns-message'
          });
          
          // 如果经过重试，添加重试信息
          if (retryResult.retried > 0) {
            responseHeaders.set('X-DNS-Retried', `${retryResult.retried} times`);
          }
          
          return new Response(retryResult.response.body, {
            status: retryResult.response.status,
            statusText: retryResult.response.statusText,
            headers: responseHeaders
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
    
    // 检查输出格式
    const outputFormat = url.searchParams.get(FORMAT_PARAM) || 'default';
    
    if (outputFormat === 'simple') {
      try {
        // 获取响应体
        const dnsResponseBody = await result.response.arrayBuffer();
        
        // 始终显示所有类型记录
        let recordTypes = extractAllRecordsFromDNSResponse(dnsResponseBody);
        
        // 如果是ANY类型查询且返回的记录为空，尝试查询多种常见记录类型
        if ((queryParams.get('type') || 'ANY').toUpperCase() === 'ANY' && 
            Object.keys(recordTypes).length === 0) {
          
          console.log("ANY类型查询返回空结果，尝试查询多种记录类型");
          
          // 要查询的常见DNS记录类型
          const recordTypesToQuery = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS'];
          let combinedRecords = {};
          
          // 为每种类型创建新的查询
          for (const recType of recordTypesToQuery) {
            const typeQueryParams = new URLSearchParams(queryParams);
            typeQueryParams.set('type', recType);
            
            // 尝试查询特定类型记录
            const typeResult = await queryWithRetry(result.server, typeQueryParams, request);
            
            if (!typeResult.error && typeResult.response) {
              const typeResponseBody = await typeResult.response.arrayBuffer();
              const typeRecords = extractAllRecordsFromDNSResponse(typeResponseBody);
              
              // 合并结果
              Object.assign(combinedRecords, typeRecords);
            }
          }
          
          // 如果合并后有结果，使用合并的结果
          if (Object.keys(combinedRecords).length > 0) {
            recordTypes = combinedRecords;
          }
        }
        
        // 构建响应输出
        const allTypesOutput = {
          domain: domainName,
          records: recordTypes,
          server: result.server,
          response_time_ms: result.time
        };
        
        // 根据请求Accept头确定输出格式
        const acceptHeader = request.headers.get('Accept') || '';
        if (acceptHeader.includes('text/plain')) {
          // 纯文本输出
          let textOutput = `域名: ${domainName}\n`;
          textOutput += `服务器: ${result.server}\n`;
          textOutput += `响应时间: ${result.time}ms\n\n`;
          
          // 添加各种记录
          Object.keys(recordTypes).forEach(recordType => {
            textOutput += `== ${recordType} 记录 ==\n`;
            recordTypes[recordType].forEach((record, index) => {
              textOutput += `${index + 1}. ${record.name} `;
              
              if (recordType === 'MX') {
                textOutput += `[优先级: ${record.value.preference}] ${record.value.exchange}\n`;
              } else {
                textOutput += `${record.value}\n`;
              }
            });
            textOutput += '\n';
          });
          
          if (Object.keys(recordTypes).length === 0) {
            textOutput += "未找到任何记录\n";
          }
          
          return new Response(textOutput, {
            status: 200,
            headers: {
              'Content-Type': 'text/plain; charset=utf-8',
              'Access-Control-Allow-Origin': '*',
              'Cache-Control': 'public, max-age=60',
              'X-DNS-Upstream': result.server,
              'X-DNS-Response-Time': `${result.time}ms`
            }
          });
        } else {
          // 返回JSON输出
          return new Response(JSON.stringify(allTypesOutput, null, 2), {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*',
              'Cache-Control': 'public, max-age=60',
              'X-DNS-Upstream': result.server,
              'X-DNS-Response-Time': `${result.time}ms`
            }
          });
        }
      } catch (error) {
        console.error('处理简单输出时出错:', error);
        // 继续使用普通响应
      }
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
        'Content-Type': 'application/json; charset=utf-8',
        'Access-Control-Allow-Origin': '*',
        'X-Error-Source': 'DNS-Resolver',
        'X-Error-Type': 'Upstream failure'
      }
    });
  }
} 
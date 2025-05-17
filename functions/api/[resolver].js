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
  
  // 处理记录类型
  // 注意：多数DNS服务器已经实现RFC8482，不再完全支持ANY查询
  // 如果遇到ANY查询失败，系统会自动退回到单独查询多种记录类型
  if (typeof recordType === 'string') {
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
      default: 
        // 尝试解析为数字
        const typeNum = parseInt(recordType);
        qtype = !isNaN(typeNum) ? typeNum : 255; // 如果无效，默认使用ANY
    }
  } else {
    // 非字符串类型，可能是数字
    qtype = parseInt(recordType) || 255;
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
    // 注意：很多DNS服务器不完全支持ANY查询，依据RFC8482
    // 部分服务器会拒绝ANY查询并返回NOTIMP，此时我们会自动查询常见记录类型
    // Google使用JSON格式响应，可能需要特殊处理
    const type = queryParams.get('type') || 'ANY';
    
    // 调试信息
    console.log(`查询服务器 ${server} 记录类型: ${type}`);
    
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
    
    // 检查是否是ANY类型查询
    if ((type || '').toUpperCase() === 'ANY') {
      // 尝试提前检测RFC8482响应
      const contentType = response.headers.get('Content-Type');
      if (contentType) {
        // 获取响应克隆，这样不会消耗原始响应
        const responseClone = response.clone();
        try {
          // 检查内容类型是否为DNS消息
          if (contentType.includes('application/dns-message')) {
            const buffer = await responseClone.arrayBuffer();
            const view = new DataView(buffer);
            
            // 检查回答数量和RCODE
            const ancount = view.getUint16(6); // 回答计数
            const rcode = view.getUint16(2) & 0x000F; // 错误码
            
            // 如果回答为0或返回NXDOMAIN (rcode=3)或NOTIMP (rcode=4)
            if (ancount === 0 || rcode === 3 || rcode === 4) {
              console.log(`服务器 ${server} 对ANY查询返回了无结果或错误(rcode=${rcode})`);
            }
          } 
          // 检查内容类型是否为JSON (Google和某些服务器使用)
          else if (contentType.includes('application/json')) {
            // 记录为特殊情况，可能需要特殊处理
            console.log(`服务器 ${server} 返回JSON格式响应，可能需要特殊处理`);
          }
        } catch (e) {
          console.error('预检DNS响应失败:', e);
        }
      }
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
    console.error(`查询DNS服务器 ${server} 失败:`, error.message);
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
      const isTypeA = (type === 1 && (recordType.toUpperCase() === 'A' || recordType.toUpperCase() === 'ANY'));
      const isTypeAAAA = (type === 28 && (recordType.toUpperCase() === 'AAAA' || recordType.toUpperCase() === 'ANY'));
      
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
    const header = {
      id: view.getUint16(0),
      flags: view.getUint16(2),
      qdcount: view.getUint16(4), // 问题计数
      ancount: view.getUint16(6), // 回答计数
      nscount: view.getUint16(8), // 权威记录计数
      arcount: view.getUint16(10) // 附加记录计数
    };
    
    // 提取RCODE (错误代码)
    const rcode = header.flags & 0x000F;
    
    // 如果是NXDOMAIN (rcode=3)或其他错误，记录到结果中
    if (rcode !== 0) {
      const rcodeMessages = {
        0: '没有错误',
        1: '格式错误',
        2: '服务器失败',
        3: '域名不存在 (NXDOMAIN)',
        4: '查询类型不支持',
        5: '服务器拒绝处理',
        6: 'YX域',
        7: 'YX RR Set',
        8: 'NX RR Set',
        9: '您不是授权方',
        10: '域名不在区域中',
        11: '11 (保留)',
        12: '12 (保留)',
        13: '13 (保留)',
        14: '14 (保留)',
        15: '15 (保留)'
      };
      
      const records = {
        ERROR: [{
          name: 'RCODE',
          value: `${rcode} - ${rcodeMessages[rcode] || '未知错误'}`,
          ttl: 0
        }]
      };
      
      // 如果是RCODE=4（查询类型不支持），这可能是RFC8482的暗示
      if (rcode === 4) {
        records.NOTE = [{
          name: 'RFC8482',
          value: '服务器返回RCODE=4，表明不支持查询类型，可能是对ANY查询的RFC8482响应',
          ttl: 0
        }];
      }
      
      return records;
    }
    
    // 如果没有回答记录但不是因为错误
    if (header.ancount === 0 && rcode === 0) {
      return {
        NOTE: [{
          name: 'NO_RECORDS',
          value: '查询成功，但没有找到匹配记录',
          ttl: 0
        }]
      };
    }
    
    // 跳过查询部分
    let offset = 12; // DNS头部长度为12字节
    
    // 跳过所有问题
    for (let i = 0; i < header.qdcount; i++) {
      // 跳过域名
      while (true) {
        if (offset >= buffer.byteLength) {
          return {
            ERROR: [{
              name: 'PARSE_ERROR',
              value: '解析DNS响应时超出缓冲区范围',
              ttl: 0
            }]
          };
        }
        
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
      CAA: [],
      OTHER: [] // 其他未明确处理的记录类型
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
        
        // 检查缓冲区边界
        if (currentOffset >= buffer.byteLength) {
          return { name: '[解析错误:访问超出缓冲区]', offset: startOffset };
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
          
          // 检查缓冲区边界
          if (currentOffset + 1 >= buffer.byteLength) {
            return { name: '[解析错误:访问超出缓冲区]', offset: startOffset };
          }
          
          // 计算跳转位置
          const jumpOffset = ((len & 0x3f) << 8) | view.getUint8(currentOffset + 1);
          
          // 检查跳转目标有效性
          if (jumpOffset >= buffer.byteLength) {
            return { name: '[解析错误:跳转目标无效]', offset: startOffset };
          }
          
          currentOffset = jumpOffset;
          jumpCount++;
          continue;
        }
        
        // 读取标签
        currentOffset += 1;
        
        // 检查缓冲区边界
        if (currentOffset + len > buffer.byteLength) {
          return { name: '[解析错误:标签超出缓冲区]', offset: startOffset };
        }
        
        let label = '';
        for (let i = 0; i < len; i++) {
          // 只使用可打印字符
          const charCode = view.getUint8(currentOffset + i);
          if (charCode >= 32 && charCode < 127) {
            label += String.fromCharCode(charCode);
          } else {
            label += '.'; // 用点替换不可打印字符
          }
        }
        result += (result ? '.' : '') + label;
        currentOffset += len;
      }
      
      return { 
        name: result, 
        offset: jumping ? startOffset + 2 : currentOffset // 如果发生了跳转，返回原始位置+2
      };
    };
    
    // 尝试解析所有回答记录
    try {
      for (let i = 0; i < header.ancount; i++) {
        // 安全检查 - 确保偏移量在缓冲区内
        if (offset + 10 >= buffer.byteLength) {
          break; // 退出循环避免访问超出范围的内存
        }
        
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
        
        // 安全检查 - 确保rdlength在合理范围内
        if (rdlength > 1000 || offset + rdlength > buffer.byteLength) {
          // 数据长度不合理或会超出缓冲区
          records.OTHER.push({
            name: domainName,
            recordType: type,
            rdLength: rdlength,
            value: '数据长度异常或超出缓冲区',
            ttl
          });
          
          // 尝试安全跳过这个记录
          if (offset + rdlength <= buffer.byteLength) {
            offset += rdlength;
          } else {
            break; // 退出循环，避免继续解析可能损坏的数据
          }
          continue;
        }
        
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
              
              // 安全检查
              if (txtOffset < buffer.byteLength) {
                const txtLength = view.getUint8(txtOffset);
                txtOffset++;
                
                // 确保不会超出缓冲区
                if (txtOffset + txtLength <= offset + rdlength && txtOffset + txtLength <= buffer.byteLength) {
                  for (let j = 0; j < txtLength; j++) {
                    const charCode = view.getUint8(txtOffset + j);
                    // 只接受可打印字符
                    if (charCode >= 32 && charCode < 127) {
                      txtValue += String.fromCharCode(charCode);
                    } else {
                      txtValue += '.'; // 用点替换不可打印字符
                    }
                  }
                }
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
            
          case 12: // PTR记录
            {
              const ptrResult = readDomainName(offset);
              records.PTR.push({ name: domainName, value: ptrResult.name, ttl });
            }
            break;
            
          case 6: // SOA记录
            {
              const mnameDomain = readDomainName(offset);
              let soaOffset = mnameDomain.offset;
              const rnameDomain = readDomainName(soaOffset);
              soaOffset = rnameDomain.offset;
              
              // 安全检查 - 确保有足够的数据来读取SOA的5个32位值
              if (soaOffset + 20 <= offset + rdlength && soaOffset + 20 <= buffer.byteLength) {
                const serial = view.getUint32(soaOffset);
                const refresh = view.getUint32(soaOffset + 4);
                const retry = view.getUint32(soaOffset + 8);
                const expire = view.getUint32(soaOffset + 12);
                const minimum = view.getUint32(soaOffset + 16);
                
                records.SOA.push({
                  name: domainName,
                  value: {
                    mname: mnameDomain.name,
                    rname: rnameDomain.name,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum
                  },
                  ttl
                });
              } else {
                // 数据不完整，作为OTHER类型记录处理
                records.OTHER.push({
                  name: domainName,
                  recordType: 'SOA(incomplete)',
                  rdLength: rdlength,
                  value: {
                    mname: mnameDomain.name,
                    rname: rnameDomain.name
                  },
                  ttl
                });
              }
            }
            break;
            
          case 257: // CAA记录
            {
              if (rdlength >= 2) {
                const flags = view.getUint8(offset);
                let tagLength = view.getUint8(offset + 1);
                
                // 安全检查
                if (offset + 2 + tagLength < offset + rdlength && offset + 2 + tagLength < buffer.byteLength) {
                  let tag = '';
                  for (let j = 0; j < tagLength; j++) {
                    tag += String.fromCharCode(view.getUint8(offset + 2 + j));
                  }
                  
                  let valueLength = rdlength - 2 - tagLength;
                  let value = '';
                  
                  // 安全检查
                  if (offset + 2 + tagLength + valueLength <= buffer.byteLength) {
                    for (let j = 0; j < valueLength; j++) {
                      const charCode = view.getUint8(offset + 2 + tagLength + j);
                      // 只接受可打印字符
                      if (charCode >= 32 && charCode < 127) {
                        value += String.fromCharCode(charCode);
                      } else {
                        value += '.'; // 用点替换不可打印字符
                      }
                    }
                  }
                  
                  records.CAA.push({
                    name: domainName,
                    value: { flags, tag, value },
                    ttl
                  });
                } else {
                  // 数据不完整，作为OTHER类型记录处理
                  records.OTHER.push({
                    name: domainName,
                    recordType: 'CAA(incomplete)',
                    rdLength: rdlength,
                    ttl
                  });
                }
              }
            }
            break;
            
          case 33: // SRV记录
            {
              // 安全检查
              if (offset + 6 < buffer.byteLength) {
                const priority = view.getUint16(offset);
                const weight = view.getUint16(offset + 2);
                const port = view.getUint16(offset + 4);
                const targetResult = readDomainName(offset + 6);
                
                records.SRV.push({
                  name: domainName,
                  value: {
                    priority,
                    weight,
                    port,
                    target: targetResult.name
                  },
                  ttl
                });
              } else {
                // 数据不完整，作为OTHER类型记录处理
                records.OTHER.push({
                  name: domainName,
                  recordType: 'SRV(incomplete)',
                  rdLength: rdlength,
                  ttl
                });
              }
            }
            break;
            
          default:
            // 处理未知类型的记录 - 安全地存储记录类型和长度
            let recordTypeName = 'TYPE' + type;
            
            // 常见的DNS记录类型映射
            const typeMap = {
              13: 'HINFO',   // 主机信息
              17: 'RP',      // 负责人
              18: 'AFSDB',   // AFS数据库
              19: 'X25',     // X.25 PSDN地址
              20: 'ISDN',    // ISDN地址
              24: 'SIG',     // 签名
              25: 'KEY',     // 密钥
              29: 'LOC',     // 位置信息
              43: 'DS',      // 委托签名者
              44: 'SSHFP',   // SSH指纹
              45: 'IPSECKEY',// IPSEC密钥
              46: 'RRSIG',   // DNSSEC签名
              47: 'NSEC',    // 下一个安全记录
              48: 'DNSKEY',  // DNS密钥
              50: 'NSEC3',   // NSEC记录版本3
              51: 'NSEC3PARAM', // NSEC3参数
              256: 'URI',    // 统一资源标识符
              65281: 'SPF'   // SPF记录(弃用)
            };
            
            if (typeMap[type]) {
              recordTypeName = typeMap[type];
            }
            
            // 尝试读取记录内容的安全方法
            let value = '二进制数据';
            try {
              // 如果是HINFO记录，尝试解析为文本
              if (type === 13) { // HINFO
                let hinfo = { cpu: '', os: '' };
                
                // 读取CPU字符串
                if (offset < buffer.byteLength) {
                  const cpuLength = view.getUint8(offset);
                  if (offset + 1 + cpuLength <= offset + rdlength && offset + 1 + cpuLength <= buffer.byteLength) {
                    for (let j = 0; j < cpuLength; j++) {
                      const charCode = view.getUint8(offset + 1 + j);
                      if (charCode >= 32 && charCode < 127) {
                        hinfo.cpu += String.fromCharCode(charCode);
                      }
                    }
                    // 读取OS字符串
                    const osOffset = offset + 1 + cpuLength;
                    if (osOffset < buffer.byteLength) {
                      const osLength = view.getUint8(osOffset);
                      if (osOffset + 1 + osLength <= offset + rdlength && osOffset + 1 + osLength <= buffer.byteLength) {
                        for (let j = 0; j < osLength; j++) {
                          const charCode = view.getUint8(osOffset + 1 + j);
                          if (charCode >= 32 && charCode < 127) {
                            hinfo.os += String.fromCharCode(charCode);
                          }
                        }
                      }
                    }
                  }
                }
                value = hinfo;
              }
            } catch (e) {
              console.error('解析特殊记录类型时出错:', e);
              value = '解析错误';
            }
            
            records.OTHER.push({
              name: domainName,
              recordType: recordTypeName,
              rdLength: rdlength,
              value: value,
              ttl
            });
        }
        
        // 移动到下一条记录
        offset += rdlength;
      }
    } catch (error) {
      console.error('解析DNS记录时出错:', error);
      // 仍然返回已解析的记录，不完全放弃
      if (Object.values(records).flat().length === 0) {
        // 如果没有解析到任何记录，返回错误
        return {
          ERROR: [{
            name: 'PARSE_ERROR',
            value: '解析DNS响应记录时出错: ' + error.message,
            ttl: 0
          }]
        };
      }
    }
    
    // 检查是否有任何记录类型，如果没有，返回NOTE
    const hasAnyRecords = Object.entries(records).some(([type, recs]) => 
      type !== 'NOTE' && type !== 'ERROR' && recs.length > 0
    );
    
    if (!hasAnyRecords) {
      records.NOTE = [{
        name: 'NO_RECORDS',
        value: '解析成功，但没有找到有效记录',
        ttl: 0
      }];
    }
    
    // 移除空的记录类型数组
    Object.keys(records).forEach(key => {
      if (records[key].length === 0) {
        delete records[key];
      }
    });
    
    return records;
  } catch (error) {
    console.error('解析DNS响应时出错:', error);
    return {
      ERROR: [{
        name: 'PARSE_ERROR',
        value: '解析DNS响应时出错: ' + error.message,
        ttl: 0
      }]
    };
  }
}

// 检查是否是RFC8482响应（禁用ANY查询的响应）
const isRFC8482Response = (records) => {
  // 确保records是有效对象
  if (!records || typeof records !== 'object') {
    return false;
  }
  
  // 检查是否有PTR记录并且值包含RFC8482
  if (records.PTR && Array.isArray(records.PTR) && records.PTR.length > 0) {
    for (const ptr of records.PTR) {
      if (!ptr || typeof ptr !== 'object') continue;
      
      const ptrValue = ptr.value;
      if (typeof ptrValue === 'string' && 
          (ptrValue.includes('RFC8482') || ptrValue.includes('RFC 8482'))) {
        return true;
      }
    }
  }
  
  // 检查返回的记录总数，可能表明是RFC8482响应
  // ANY请求通常应该返回多个记录类型
  const totalTypes = Object.keys(records).length;
  if (totalTypes === 1 && records.hasOwnProperty('PTR')) {
    return true;
  }
  
  // 检查是否有TXT记录提到RFC8482
  if (records.TXT && records.TXT.length > 0) {
    for (const txt of records.TXT) {
      const txtValue = txt.value;
      if (typeof txtValue === 'string' && 
          (txtValue.includes('RFC8482') || txtValue.includes('RFC 8482'))) {
        return true;
      }
    }
  }
  
  // 检查是否有一个CNAME记录指向rfc8482
  if (records.CNAME && records.CNAME.length > 0) {
    for (const cname of records.CNAME) {
      const cnameValue = cname.value;
      if (typeof cnameValue === 'string' && 
          (cnameValue.includes('rfc8482') || cnameValue.includes('rfc-8482'))) {
        return true;
      }
    }
  }
  
  return false;
};

// 从记录集合构建完整的DNS响应消息
function buildDNSResponseFromRecords(domainName, records) {
  // DNS 响应ID（随机16位）
  const id = Math.floor(Math.random() * 65536);
  
  // 第一个字节: 标准响应，递归可用
  // 第二个字节: RD位和RA位设置为1（期望递归+递归可用）
  const flags = 0x8180; // 二进制：10000001 10000000
  
  // 计算问题和回答数量
  const qdcount = 1; // 一个问题（原始查询）
  
  // 计算所有记录的总数
  let ancount = 0;
  for (const type in records) {
    if (type !== 'NOTE' && type !== 'ERROR') { // 排除非标准DNS记录类型
      ancount += records[type].length;
    }
  }
  
  // 其他字段都是0
  const nscount = 0;
  const arcount = 0;
  
  // 构建查询问题部分
  // 拆分域名为各段标签
  const labels = domainName.split('.');
  
  // 计算域名编码后的长度
  const domainBytes = labels.reduce((acc, label) => acc + label.length + 1, 0) + 1;
  
  // 分配足够的空间 - 估算需要的空间
  // 头部(12字节) + 问题部分(域名+4字节) + 回答部分(每个记录约20-50字节)
  const estimatedSize = 12 + domainBytes + 4 + (ancount * 50); 
  const message = new Uint8Array(estimatedSize);
  
  // 填充头部
  message[0] = id >> 8; // ID高字节
  message[1] = id & 0xff; // ID低字节
  message[2] = flags >> 8; // flags高字节
  message[3] = flags & 0xff; // flags低字节
  message[4] = qdcount >> 8; // QDCOUNT高字节
  message[5] = qdcount & 0xff; // QDCOUNT低字节
  message[6] = ancount >> 8; // ANCOUNT高字节
  message[7] = ancount & 0xff; // ANCOUNT低字节
  message[8] = nscount >> 8; // NSCOUNT高字节
  message[9] = nscount & 0xff; // NSCOUNT低字节
  message[10] = arcount >> 8; // ARCOUNT高字节
  message[11] = arcount & 0xff; // ARCOUNT低字节
  
  // 填充查询域（问题部分）
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
  
  // 添加ANY查询类型(255)和IN类(1)
  message[offset++] = 0; // QTYPE高字节
  message[offset++] = 255; // QTYPE低字节 - ANY
  message[offset++] = 0; // QCLASS高字节
  message[offset++] = 1; // QCLASS低字节 - IN
  
  // 添加各类型的记录
  const recordTypeMappings = {
    'A': 1,
    'NS': 2,
    'CNAME': 5,
    'SOA': 6,
    'PTR': 12,
    'MX': 15,
    'TXT': 16,
    'AAAA': 28,
    'SRV': 33,
    'CAA': 257
  };
  
  // 添加A记录
  if (records.A && records.A.length > 0) {
    for (const record of records.A) {
      // 添加域名引用（压缩指针）
      message[offset++] = 0xc0; // 压缩指针标记
      message[offset++] = 12; // 指向头部后的域名位置
      
      // 添加记录类型
      message[offset++] = 0; // A记录类型高字节
      message[offset++] = 1; // A记录类型低字节
      
      // 添加记录类
      message[offset++] = 0; // IN类高字节
      message[offset++] = 1; // IN类低字节
      
      // 添加TTL（生存时间）- 使用记录中的TTL或默认值
      const ttl = record.ttl || 300;
      message[offset++] = (ttl >> 24) & 0xff;
      message[offset++] = (ttl >> 16) & 0xff;
      message[offset++] = (ttl >> 8) & 0xff;
      message[offset++] = ttl & 0xff;
      
      // 添加数据长度 - A记录总是4字节
      message[offset++] = 0; // 长度高字节
      message[offset++] = 4; // 长度低字节
      
      // 添加IP地址
      const ipParts = record.value.split('.');
      for (const part of ipParts) {
        message[offset++] = parseInt(part);
      }
    }
  }
  
  // 添加AAAA记录
  if (records.AAAA && records.AAAA.length > 0) {
    for (const record of records.AAAA) {
      // 添加域名引用（压缩指针）
      message[offset++] = 0xc0; // 压缩指针标记
      message[offset++] = 12; // 指向头部后的域名位置
      
      // 添加记录类型
      message[offset++] = 0; // AAAA记录类型高字节
      message[offset++] = 28; // AAAA记录类型低字节
      
      // 添加记录类
      message[offset++] = 0; // IN类高字节
      message[offset++] = 1; // IN类低字节
      
      // 添加TTL（生存时间）
      const ttl = record.ttl || 300;
      message[offset++] = (ttl >> 24) & 0xff;
      message[offset++] = (ttl >> 16) & 0xff;
      message[offset++] = (ttl >> 8) & 0xff;
      message[offset++] = ttl & 0xff;
      
      // 添加数据长度 - AAAA记录总是16字节
      message[offset++] = 0; // 长度高字节
      message[offset++] = 16; // 长度低字节
      
      // 添加IPv6地址
      // 将IPv6地址分解为16位块
      const ipv6 = record.value;
      try {
        // 确保IPv6地址是完整格式
        const fullIpv6 = expandIPv6Address(ipv6);
        const parts = fullIpv6.split(':');
        
        // IPv6地址应有8组16位值
        if (parts.length === 8) {
          for (const part of parts) {
            const value = parseInt(part, 16) || 0;
            message[offset++] = (value >> 8) & 0xff; // 高字节
            message[offset++] = value & 0xff; // 低字节
          }
        } else {
          // 如果格式不对，使用0填充
          for (let i = 0; i < 8; i++) {
            message[offset++] = 0;
            message[offset++] = 0;
          }
        }
      } catch (e) {
        console.error('解析IPv6地址时出错:', e);
        // 使用0填充16字节
        for (let i = 0; i < 8; i++) {
          message[offset++] = 0;
          message[offset++] = 0;
        }
      }
    }
  }
  
  // 添加CNAME记录
  if (records.CNAME && records.CNAME.length > 0) {
    for (const record of records.CNAME) {
      // 添加域名引用（压缩指针）
      message[offset++] = 0xc0; // 压缩指针标记
      message[offset++] = 12; // 指向头部后的域名位置
      
      // 添加记录类型
      message[offset++] = 0; // CNAME记录类型高字节
      message[offset++] = 5; // CNAME记录类型低字节
      
      // 添加记录类
      message[offset++] = 0; // IN类高字节
      message[offset++] = 1; // IN类低字节
      
      // 添加TTL（生存时间）
      const ttl = record.ttl || 300;
      message[offset++] = (ttl >> 24) & 0xff;
      message[offset++] = (ttl >> 16) & 0xff;
      message[offset++] = (ttl >> 8) & 0xff;
      message[offset++] = ttl & 0xff;
      
      // 编码CNAME目标域名
      const cnameParts = record.value.split('.');
      const cnameLength = cnameParts.reduce((acc, part) => acc + part.length + 1, 1);
      
      // 添加数据长度
      message[offset++] = (cnameLength >> 8) & 0xff;
      message[offset++] = cnameLength & 0xff;
      
      // 添加域名各部分
      for (const part of cnameParts) {
        message[offset++] = part.length;
        for (let i = 0; i < part.length; i++) {
          message[offset++] = part.charCodeAt(i);
        }
      }
      // 结束域名
      message[offset++] = 0;
    }
  }
  
  // 添加TXT记录
  if (records.TXT && records.TXT.length > 0) {
    for (const record of records.TXT) {
      // 添加域名引用（压缩指针）
      message[offset++] = 0xc0; // 压缩指针标记
      message[offset++] = 12; // 指向头部后的域名位置
      
      // 添加记录类型
      message[offset++] = 0; // TXT记录类型高字节
      message[offset++] = 16; // TXT记录类型低字节
      
      // 添加记录类
      message[offset++] = 0; // IN类高字节
      message[offset++] = 1; // IN类低字节
      
      // 添加TTL（生存时间）
      const ttl = record.ttl || 300;
      message[offset++] = (ttl >> 24) & 0xff;
      message[offset++] = (ttl >> 16) & 0xff;
      message[offset++] = (ttl >> 8) & 0xff;
      message[offset++] = ttl & 0xff;
      
      // 文本内容 - TXT记录的特殊格式：长度前缀字符串
      const txtValue = record.value || '';
      const txtBytes = Math.min(255, txtValue.length);
      
      // 添加数据长度 (文本长度 + 1个字节的长度字段)
      message[offset++] = 0;
      message[offset++] = txtBytes + 1;
      
      // 添加文本长度字节
      message[offset++] = txtBytes;
      
      // 添加文本字符
      for (let i = 0; i < txtBytes; i++) {
        message[offset++] = txtValue.charCodeAt(i);
      }
    }
  }
  
  // 返回实际使用的部分
  return message.slice(0, offset);
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
      const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$/;
      
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
    
    // 获取响应体，用于检查和处理RFC8482和空响应情况
    let dnsResponseBody;
    try {
      const clonedResponse = result.response.clone();
      dnsResponseBody = await clonedResponse.arrayBuffer();
    } catch (bodyError) {
      console.error('获取DNS响应体失败:', bodyError);
      dnsResponseBody = new ArrayBuffer(0);
    }
    
    // 检查是否需要处理ANY查询的特殊情况
    const isAnyQuery = (queryParams.get('type') || 'ANY').toUpperCase() === 'ANY';
    let needRequery = false;
    let requeriedRecords = null;
    
    // 检查是否为Google JSON格式的响应
    const isGoogleJsonResponse = result.response.headers.get('Content-Type')?.includes('application/json') && 
                               result.server.includes('dns.google');
    
    // 服务器处理逻辑优化 - 根据服务器类型选择最佳处理方式
    const isCloudflare = result.server === "https://cloudflare-dns.com/dns-query";
    const isGoogle = result.server.includes('dns.google');
    const isAliDNS = result.server.includes('dns.alidns.com');
    const isDNSPod = result.server.includes('doh.pub');
    
    // 确定是否需要重新查询
    // 对于Cloudflare，只在需要时重新查询；对于其他服务器，总是对ANY查询进行重新查询
    if ((isAnyQuery && !isCloudflare) || isGoogleJsonResponse) {
      needRequery = true;
      console.log(`非Cloudflare服务器(${result.server})的ANY查询或特殊格式，将重新查询各记录类型`);
    } else if (isAnyQuery && isCloudflare) {
      // 对于Cloudflare，尝试检查其ANY响应是否有效
      try {
        if (dnsResponseBody && dnsResponseBody.byteLength > 0) {
          const recordTypes = extractAllRecordsFromDNSResponse(dnsResponseBody);
          
          // 检查是否是RFC8482响应或空响应
          const metRFC8482 = isRFC8482Response(recordTypes);
          const emptyResponse = !recordTypes || Object.keys(recordTypes).length === 0 || 
            (Object.keys(recordTypes).length === 1 && recordTypes.NOTE);
            
          // 检查RCODE
          let rcode = 0;
          if (dnsResponseBody.byteLength >= 4) {
            rcode = new DataView(dnsResponseBody).getUint16(2) & 0x000F;
            const isNXDomain = rcode === 3 || rcode === 4;
            
            // 只有在特定条件下才重新查询
            if (emptyResponse || metRFC8482 || isNXDomain) {
              console.log(`Cloudflare ANY查询返回特殊响应 (rcode=${rcode})，尝试查询多种记录类型`);
              needRequery = true;
            }
          }
        }
      } catch (parseError) {
        console.error('解析Cloudflare DNS响应时出错:', parseError);
        needRequery = true;
      }
    }
    
    // 处理重新查询
    if (needRequery) {
      try {
        console.log(`服务器(${result.server})需要重新查询各类型记录`);
        
        // 要查询的常见DNS记录类型
        const recordTypesToQuery = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA'];
        const combinedRecords = {};
        
        // 为每种类型创建新的查询
        for (const recType of recordTypesToQuery) {
          const typeQueryParams = new URLSearchParams(queryParams);
          typeQueryParams.set('type', recType);
          
          // 尝试查询特定类型记录
          try {
            const typeResult = await queryWithRetry(result.server, typeQueryParams, request);
            
            if (!typeResult.error && typeResult.response) {
              try {
                const typeResponseBody = await typeResult.response.arrayBuffer();
                const typeRecords = extractAllRecordsFromDNSResponse(typeResponseBody);
                
                // 合并结果
                for (const [type, records] of Object.entries(typeRecords)) {
                  // 跳过NOTE类型记录的合并，避免产生重复的NO_RECORDS记录
                  if (type === 'NOTE' && records.some(r => r.name === 'NO_RECORDS')) {
                    continue;
                  }
                  
                  // 跳过NOTE类型的重复记录
                  if (type === 'NOTE' && (combinedRecords[type] || []).some(r => r.name === 'NO_RECORDS')) {
                    if (!records.some(r => r.name === 'NO_RECORDS')) {
                      if (!combinedRecords[type]) {
                        combinedRecords[type] = records;
                      } else {
                        combinedRecords[type] = [...combinedRecords[type], ...records];
                      }
                    }
                  } else if (!combinedRecords[type]) {
                    combinedRecords[type] = records;
                  } else {
                    combinedRecords[type] = [...combinedRecords[type], ...records];
                  }
                }
              } catch (parseError) {
                console.error(`解析${recType}记录响应时出错:`, parseError);
              }
            }
          } catch (queryError) {
            console.error(`查询${recType}记录时出错:`, queryError);
          }
        }
        
        // 保存结果以供后续处理
        if (Object.keys(combinedRecords).length > 0) {
          requeriedRecords = combinedRecords;
        }
      } catch (error) {
        console.error('重新查询各类型记录时出错:', error);
      }
    }
    
    if (outputFormat === 'simple') {
      try {
        // 使用已经获取的响应体或重新查询的结果
        let recordTypes = requeriedRecords;
        
        // 如果没有重新查询的结果，使用原始响应
        if (!recordTypes && dnsResponseBody && dnsResponseBody.byteLength > 0) {
          recordTypes = extractAllRecordsFromDNSResponse(dnsResponseBody);
        }
        
        // 确保recordTypes存在
        recordTypes = recordTypes || {};
        
        // 清理OTHER类型的记录，确保它们可以被安全序列化
        if (recordTypes.OTHER && recordTypes.OTHER.length > 0) {
          recordTypes.OTHER = recordTypes.OTHER.map(record => {
            // 深拷贝以避免修改原始对象
            const safeRecord = { ...record };
            
            // 对值进行特殊处理，确保它是可序列化的
            if (typeof safeRecord.value === 'object' && safeRecord.value !== null) {
              // 对象类型值，如HINFO记录中的{ cpu, os }
              safeRecord.value = JSON.parse(JSON.stringify(safeRecord.value));
            } else if (typeof safeRecord.value !== 'string' && typeof safeRecord.value !== 'number') {
              // 如果值不是字符串、数字或对象，转换为字符串
              safeRecord.value = String(safeRecord.value || '');
            }
            
            return safeRecord;
          });
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
          // 在JSON序列化前清理记录，移除可能导致问题的二进制数据
          // 清理OTHER类型的记录，确保只包含安全的字段
          if (allTypesOutput.records && allTypesOutput.records.OTHER) {
            allTypesOutput.records.OTHER = allTypesOutput.records.OTHER.map(record => ({
              name: record.name,
              recordType: record.recordType,
              rdLength: record.rdLength,
              ttl: record.ttl
            }));
          }
          
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
        console.error('处理简洁输出时出错:', error);
        // 继续使用普通响应
      }
    } else if (needRequery && requeriedRecords) {
      // 对于标准模式下的ANY查询，如果单独查询各类型记录成功，
      // 需要构建一个类似RFC8482响应的DNS消息以兼容标准DNS客户端
      try {
        // 记录各记录类型数量的日志
        console.log(`构建合成DNS响应:`, Object.keys(requeriedRecords).map(type => 
          `${type}=${requeriedRecords[type]?.length || 0}`).join(', '));
        
        // 创建一个新的DNS响应消息
        const responseMessage = buildDNSResponseFromRecords(domainName, requeriedRecords);
        
        console.log(`构建了 ${responseMessage.byteLength} 字节的DNS响应消息`);
        
        return new Response(responseMessage, {
          status: 200,
          headers: new Headers({
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST',
            'Cache-Control': 'public, max-age=60',
            'X-DNS-Upstream': result.server,
            'X-DNS-Response-Time': `${result.time}ms`,
            'X-DNS-ECS-Status': result.hasEcs ? `Added (${result.ecsSource})` : 'Not added',
            'X-DNS-Debug': 'RFC8482 response rebuilt with all record types',
            'X-DNS-Record-Types': Object.keys(requeriedRecords).join(','),
            'Content-Type': 'application/dns-message'
          })
        });
      } catch (error) {
        console.error('构建DNS响应消息时出错:', error);
        // 继续使用原始响应
      }
    }
    
    // 根据服务器和查询结果选择最合适的响应格式
    
    // 1. 如果重新查询成功，无论是什么服务器，都使用标准DNS消息格式
    if (needRequery && requeriedRecords && Object.keys(requeriedRecords).length > 0) {
      try {
        console.log('使用重新查询的结果构建标准DNS消息');
        
        // 创建一个新的DNS响应消息
        const responseMessage = buildDNSResponseFromRecords(domainName, requeriedRecords);
        
        return new Response(responseMessage, {
          status: 200,
          headers: new Headers({
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST',
            'Cache-Control': 'public, max-age=60',
            'X-DNS-Upstream': result.server,
            'X-DNS-Response-Time': `${result.time}ms`,
            'X-DNS-ECS-Status': result.hasEcs ? `Added (${result.ecsSource})` : 'Not added',
            'X-DNS-Debug': 'Using standard DNS message from requeried records',
            'Content-Type': 'application/dns-message'
          })
        });
      } catch (buildError) {
        console.error('构建DNS响应消息失败:', buildError);
        // 如果构建失败，尝试其他方式
      }
    }
    
    // 2. 尝试使用原始响应 - 适用于所有服务器，包括Cloudflare
    try {
      console.log(`尝试使用 ${result.server} 的原始响应`);
      const contentType = result.response.headers.get('Content-Type') || 'application/dns-message';
      
      // 始终创建响应体的新副本，避免流已消耗错误
      let responseBody;
      if (dnsResponseBody && dnsResponseBody.byteLength > 0) {
        responseBody = dnsResponseBody;  // 使用之前获取的响应体
      } else {
        // 尝试再次获取响应体
        try {
          const freshClone = result.response.clone();
          responseBody = await freshClone.arrayBuffer();
        } catch (e) {
          console.error('无法获取响应体:', e);
          // 创建一个空的DNS响应
          responseBody = new Uint8Array(12);  // 12字节的空DNS头
        }
      }
      
      return new Response(responseBody, {
        status: 200, // 强制使用200状态码，避免出现500错误
        headers: new Headers({
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST',
          'Cache-Control': 'public, max-age=60',
          'X-DNS-Upstream': result.server,
          'X-DNS-Response-Time': `${result.time}ms`,
          'X-DNS-ECS-Status': result.hasEcs ? `Added (${result.ecsSource})` : 'Not added',
          'X-DNS-Debug': 'Using original response with safe body handling',
          'Content-Type': contentType
        })
      });
    } catch (originalError) {
      console.error(`使用原始响应失败:`, originalError);
      
      // 如果原始响应处理失败，返回一个最小化的安全响应
      return new Response(new Uint8Array(12), {  // 12字节的空DNS头
        status: 200,
        headers: new Headers({
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST',
          'Cache-Control': 'no-cache',
          'X-DNS-Upstream': result.server,
          'X-DNS-Response-Time': `${result.time}ms`,
          'X-DNS-Debug': 'Fallback empty response - all processing methods failed',
          'Content-Type': 'application/dns-message'
        })
      });
    }
    
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
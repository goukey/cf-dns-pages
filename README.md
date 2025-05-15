# DNS解析加速服务 (Cloudflare Pages版本)

一个基于Cloudflare Pages的DNS解析加速服务，提供快速稳定的域名解析功能，绕过网络限制。利用Pages Functions实现后端功能。

## 功能特点

- **智能解析**：将请求分发到全球多个高速节点（Cloudflare, Google, Quad9等）
- **多节点支持**：支持在请求中动态指定上游解析节点
- **并行查询**：同时查询多个上游服务器，返回最快的结果
- **自动ECS**：智能识别客户端IP并自动设置适当的客户端子网
- **ECS支持**：支持EDNS Client Subnet，获取更精准的地理位置解析结果
- **自定义上游**：支持用户自定义任意HTTPS的DNS解析服务器
- **兼容标准**：完全兼容标准的DNS解析协议
- **低延迟**：利用Cloudflare的全球边缘网络，提供低延迟的DNS解析服务
- **无服务器**：完全基于Cloudflare Pages构建，无需维护服务器
- **简单部署**：可直接通过GitHub一键部署到Cloudflare Pages
- **IPv6支持**：完全支持IPv6地址解析和AAAA记录查询
- **默认并行查询**：默认情况下自动查询多个上游服务器，获取最快响应

## 部署指南

### 使用Cloudflare Pages部署

1. **Fork本仓库**
   
   将本仓库Fork到您的GitHub账户

2. **配置Cloudflare Pages**
   
   - 登录Cloudflare控制台
   - 进入Pages服务
   - 点击"创建项目"
   - 选择"连接到Git"，选择您Fork的仓库
   - 构建设置中选择"框架预设"为"无"
   - 高级选项中确保启用了"Functions"功能
   - 点击"保存并部署"

3. **部署完成**
   
   部署完成后，您将获得一个`*.pages.dev`的域名，可以立即使用

### 自定义域名（可选）

在Cloudflare Pages控制台中，您可以配置自定义域名：

1. 转到项目设置
2. 点击"自定义域"
3. 添加您的域名并按照提示完成DNS配置

## 使用方法

### API端点

服务主要提供一个API端点：`/api/resolver`

### 查询示例

```
# 基本查询
https://[your-domain]/api/resolver?name=example.com&type=A
# （默认会自动并行查询多个上游服务器 - cloudflare和google，返回最快的结果）

# IPv6地址查询
https://[your-domain]/api/resolver?name=example.com&type=AAAA

# 强制使用单一上游服务器模式（禁用并行查询）
https://[your-domain]/api/resolver?name=example.com&type=A&single=true

# 指定预设上游节点
https://[your-domain]/api/resolver?name=example.com&type=A&server=google

# 多节点并行查询（同时查询多个上游服务器，返回最快的结果）
https://[your-domain]/api/resolver?name=example.com&type=A&server=cloudflare,google,quad9

# 使用所有预设节点进行并行查询
https://[your-domain]/api/resolver?name=example.com&type=A&parallel=true

# 启用自动ECS (默认已启用)
https://[your-domain]/api/resolver?name=example.com&type=A&auto_ecs=true

# 禁用自动ECS
https://[your-domain]/api/resolver?name=example.com&type=A&auto_ecs=false

# 手动指定ECS获取更精准的结果
https://[your-domain]/api/resolver?name=example.com&type=A&edns_client_subnet=192.168.1.0/24

# IPv6 ECS子网指定
https://[your-domain]/api/resolver?name=example.com&type=AAAA&edns_client_subnet=2001:db8::/56

# 自定义上游服务器
https://[your-domain]/api/resolver?name=example.com&type=A&upstream=https://your-custom-doh-server.com/dns-query

# 多个自定义上游服务器
https://[your-domain]/api/resolver?name=example.com&type=A&upstream=https://dns1.example.com/dns-query,https://dns2.example.com/dns-query
```

### 在各种客户端中使用

1. **浏览器配置**
   - Firefox: 设置 -> 网络设置 -> 启用DNS-over-HTTPS -> 自定义，输入：
     `https://[your-domain]/api/resolver`

2. **DNS客户端配置**
   - AdGuard Home: 设置 -> DNS服务器 -> 添加上游DNS服务器，输入：
     `https://[your-domain]/api/resolver`
   - dnscrypt-proxy: 在配置文件中添加：
     ```toml
     [sources.yourname]
     urls = ['https://[your-domain]/api/resolver']
     ```

## 项目结构

```
cf-dns-pages/
├── functions/
│   └── api/
│       ├── [resolver].js        # 主要处理DNS解析请求的函数
│       └── [resolver].options.js # 处理CORS预检请求的函数
├── index.html                   # 主页和测试工具
└── README.md                    # 项目文档
```

## 并行查询功能

本服务支持同时查询多个上游DNS服务器，并返回最快响应的结果。这有以下优势：

1. **更快的解析速度**：自动选择响应最快的服务器结果
2. **更高的可用性**：当某个上游服务器不可用时，自动使用其他服务器的结果
3. **避免审查**：通过多服务器查询提高解析成功率

### 使用方法

1. **默认方式**：无需任何参数，默认会同时查询 Cloudflare 和 Google 两个上游服务器
   ```
   /api/resolver?name=example.com&type=A
   ```

2. **指定多个预设服务器**：使用逗号分隔多个服务器名称
   ```
   /api/resolver?name=example.com&type=A&server=cloudflare,google,quad9
   ```

3. **使用所有预设服务器**：使用parallel=true参数
   ```
   /api/resolver?name=example.com&type=A&parallel=true
   ```

4. **指定多个自定义服务器**：使用逗号分隔多个自定义DoH服务器URL
   ```
   /api/resolver?name=example.com&type=A&upstream=https://dns1.example.com/dns-query,https://dns2.example.com/dns-query
   ```

5. **禁用并行查询**：如果只想使用单一服务器（Cloudflare），可以使用single=true参数
   ```
   /api/resolver?name=example.com&type=A&single=true
   ```

所有响应都会包含以下HTTP头部信息：
- `X-DNS-Upstream`：实际提供响应的上游服务器
- `X-DNS-Response-Time`：上游服务器响应所需时间（毫秒）
- `X-DNS-Retried`：如果首次查询失败并重试成功，会包含此头部

## IPv6与AAAA记录支持

本服务完全支持IPv6地址和AAAA记录查询：

### IPv6功能

1. **AAAA记录查询**：可以直接使用`type=AAAA`参数查询域名的IPv6地址
   ```
   /api/resolver?name=example.com&type=AAAA
   ```

2. **IPv6 ECS支持**：支持IPv6格式的EDNS客户端子网
   - 自动检测：如果客户端使用IPv6连接，会自动生成IPv6 ECS（使用/56掩码）
   - 手动指定：可以手动指定IPv6格式的子网
     ```
     /api/resolver?name=example.com&type=AAAA&edns_client_subnet=2001:db8::/56
     ```

3. **IPv6地址格式支持**：支持标准IPv6地址格式、压缩格式
   - 标准格式：`2001:0db8:0000:0000:0000:ff00:0042:8329`
   - 压缩格式：`2001:db8::ff00:42:8329`

4. **默认掩码**：IPv6默认使用/56掩码，IPv4默认使用/24掩码

## ECS (EDNS Client Subnet) 支持

本服务支持 EDNS Client Subnet 扩展，允许将客户端子网信息传递给上游DNS服务器，以便返回更精准的地理位置解析结果。这对于使用CDN的网站特别有用，可以确保获取最接近用户的CDN节点。

### 自动ECS功能

为了方便普通用户，本服务默认启用了自动ECS功能：

- 系统会自动从请求头中检测用户的真实IP地址
- 从IP地址生成子网信息（IPv4默认使用/24掩码，IPv6默认使用/56掩码）
- 将子网信息传递给支持ECS的上游DNS服务器

您无需任何特殊配置，即可享受ECS带来的精准解析优势。

如需禁用自动ECS，可以在请求中添加 `auto_ecs=false` 参数。

### 手动ECS设置

您也可以通过 `edns_client_subnet` 参数手动指定客户端子网信息：

```
# IPv4子网
/api/resolver?name=example.com&type=A&edns_client_subnet=1.2.3.0/24

# IPv6子网
/api/resolver?name=example.com&type=AAAA&edns_client_subnet=2001:db8::/56
```

子网格式为 `IP地址/掩码长度`，如果不指定掩码长度，将使用默认值：IPv4为/24，IPv6为/56。

### 上游服务器ECS支持情况

不同的DNS服务器对ECS的支持情况不同：

| 服务器 | 是否支持ECS |
|-------|------------|
| Cloudflare | ❌ 不支持 |
| Google | ✅ 支持 |
| Quad9 | ✅ 支持 |
| 阿里云 | ✅ 支持 |

当查询不支持ECS的服务器时，系统会自动移除ECS参数。

### 响应头中的ECS信息

使用ECS查询时，响应中会包含以下HTTP头信息：

- `X-EDNS-Client-Subnet`：使用的客户端子网
- `X-EDNS-Client-Subnet-Used`：指示ECS是否被实际使用（取决于上游服务器是否支持）
- `X-EDNS-Client-Subnet-Source`：ECS来源（auto=自动检测，manual=手动指定）

## 关于DNS加密协议

本服务支持基于HTTPS的DNS解析（通常称为DoH）。关于DNS-over-TLS（DoT）的支持：

- 由于Cloudflare Pages平台限制（无法直接使用TCP 853端口），本服务无法直接支持DoT协议
- 但您可以：
  1. 通过本服务接入任意支持HTTPS的DNS解析服务器
  2. 使用本地DNS客户端（如dnscrypt-proxy）将DoT转换为DoH后使用本服务

## 自定义上游服务器

您可以通过以下方式使用自定义上游DNS服务器：

1. **临时使用**：在API请求中添加`upstream`参数，如：
   ```
   /api/resolver?name=example.com&type=A&upstream=https://dns.example.org/dns-query
   ```

2. **永久添加**：修改`functions/api/[resolver].js`文件中的预设服务器列表，添加新的服务器后重新部署：

   ```js
   // 预设上游服务器
   const RESOLVER_SERVERS = {
     "cloudflare": "https://cloudflare-dns.com/dns-query",
     "google": "https://dns.google/dns-query",
     "quad9": "https://dns.quad9.net/dns-query",
     "aliyun": "https://dns.alidns.com/dns-query",
     "your-custom": "https://your-custom-doh-server.com/dns-query" // 添加您的自定义服务器
   };
   
   // 同时更新ECS支持情况
   const ECS_SUPPORT = {
     "cloudflare": false,
     "google": true,
     "quad9": true,
     "aliyun": true,
     "your-custom": true // 如果您的服务器支持ECS，设为true，否则为false
   };
   ```

3. **修改默认并行查询服务器**：您可以修改默认的并行查询服务器列表：

   ```js
   // 默认并行查询的服务器列表
   const DEFAULT_PARALLEL_SERVERS = ["cloudflare", "google"];
   ```

4. **更新前端界面**：在`index.html`文件中添加新服务器的选项：

   ```html
   <label class="checkbox-item">
     <input type="checkbox" value="your-custom" class="predefined-server-checkbox"> 您的服务器名称
   </label>
   ```

   并添加ECS支持信息：

   ```html
   <span class="badge bg-success ms-2">您的服务器名称</span> <small class="text-muted">支持ECS</small>
   ```

> **注意**：自定义上游服务器必须支持HTTPS（DoH）协议。服务将验证URL是否合法且使用HTTPS协议，不符合要求的URL将被忽略。

## 常见问题

**Q: 为什么选择Cloudflare Pages而不是Workers?**
A: Pages提供了免费的静态网站托管和Functions功能，足以满足此项目需求，并且页面部署更简单。

**Q: 服务有使用限制吗？**
A: Cloudflare Pages的免费计划有每天125,000次请求和每月15GB带宽的限制，对于个人使用通常足够了。

**Q: 为什么我配置的自定义上游服务器不生效？**
A: 确保你提供的URL是完整的HTTPS URL（包含`https://`前缀），并且该服务器支持DNS-over-HTTPS协议。

**Q: 并行查询会增加带宽使用吗？**
A: 是的，并行查询会同时向多个上游服务器发送请求，这会增加一定的带宽使用量。但由于DNS查询通常很小，增加的带宽使用量通常可以忽略不计。

**Q: 为什么默认使用多个上游服务器并行查询？**
A: 并行查询多个上游服务器可以提供更快的响应速度和更高的可用性。默认情况下会同时查询Cloudflare和Google两个服务器，选择最快响应的结果返回给用户。

**Q: 如何禁用并行查询？**
A: 如果您希望使用单一上游服务器而不是并行查询，可以添加`single=true`参数：
```
/api/resolver?name=example.com&type=A&single=true
```

**Q: 我应该使用ECS吗？**
A: 系统默认已启用自动ECS功能，大多数用户无需手动配置。自动ECS会智能识别您的网络并获取更精准的解析结果，特别是对于使用CDN的网站。

**Q: 自动ECS会泄露我的隐私吗？**
A: 自动ECS仅传递您IP的网络部分（IPv4为/24子网，如123.45.67.0/24；IPv6为/56子网），而不是您的完整IP地址，能在保障隐私的同时提供较精准的解析。如仍有顾虑，可通过`auto_ecs=false`参数禁用此功能。

**Q: 为什么我启用ECS后部分查询仍然不生效？**
A: 部分DNS服务器（如Cloudflare）不支持ECS扩展，查询这些服务器时ECS参数会被自动移除。如需使用ECS，请选择支持ECS的上游服务器（如Google、Quad9或阿里云）。

**Q: 如何查询IPv6地址？**
A: 直接在查询中使用`type=AAAA`参数，例如：`/api/resolver?name=example.com&type=AAAA`。

## 安全与隐私

本服务仅转发请求，不会记录或存储任何查询内容。但请注意，上游解析服务提供商可能会根据其隐私政策记录查询日志。

自动ECS功能传递的子网信息（IPv4为/24，IPv6为/56）仅包含IP地址的网络部分，不会泄露您的完整IP，在提供精准解析的同时也能合理保护隐私。但如果对隐私有严格要求，您可以通过`auto_ecs=false`参数禁用此功能。

## 更新历史

- **2023-10-xx**：增加默认并行查询多上游服务器功能，提高查询速度和可用性
- **2023-10-xx**：增加对IPv6地址的完整支持，包括IPv6 ECS自动检测、AAAA记录查询增强，以及改进错误处理逻辑
- **2023-10-xx**：初始版本发布

## 许可证

MIT许可证

## 贡献

欢迎通过Issue和Pull Request贡献代码或提出建议！

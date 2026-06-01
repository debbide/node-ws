#!/usr/bin/env node

const os = require('os');
const http = require('http');
const fs = require('fs');
const axios = require('axios');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { Buffer } = require('buffer');
const { exec, spawn } = require('child_process');
const { performance } = require('perf_hooks');
const grpc = require('@grpc/grpc-js');
const protobuf = require('protobufjs');
const si = require('systeminformation');
const { WebSocket, createWebSocketStream } = require('ws');
const UUID = process.env.UUID || '5efabea4-f6d4-91fd-b8f0-17e004c89c60'; // 运行哪吒v1,在不同的平台需要改UUID,否则会被覆盖
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';       // 哪吒v1填写形式：nz.abc.com:8008   哪吒v0填写形式：nz.abc.com
const NEZHA_PORT = process.env.NEZHA_PORT || '';           // 哪吒v1没有此变量，v0的agent端口为{443,8443,2096,2087,2083,2053}其中之一时开启tls
const NEZHA_KEY = process.env.NEZHA_KEY || '';             // v1的NZ_CLIENT_SECRET或v0的agent端口
const NEZHA_DOH = process.env.NEZHA_DOH || '';             // 哪吒域名DoH解析地址,多个用逗号分隔,为空使用系统DNS
const DOMAIN = process.env.DOMAIN || 'your-domain.com';    // 填写项目域名或已反代的域名，不带前缀，建议填已反代的域名
const AUTO_ACCESS = String(process.env.AUTO_ACCESS || '').toLowerCase() === 'true'; // 是否开启自动访问保活,false为关闭,true为开启,需同时填写DOMAIN变量
const WSPATH = process.env.WSPATH || UUID.slice(0, 8);     // 节点路径，默认获取uuid前8位
const SUB_PATH = process.env.SUB_PATH || 'sub';            // 获取节点的订阅路径
const NAME = process.env.NAME || '';                       // 节点名称
const PORT = process.env.PORT || 3000;                     // http和ws服务端口

let uuid = UUID.replace(/-/g, ""), CurrentDomain = DOMAIN, Tls = 'tls', CurrentPort = 443, ISP = '';
const DNS_SERVERS = ['8.8.4.4', '1.1.1.1'];
const BLOCKED_DOMAINS = [
  'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
   'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org'
];

// block speedtest domains
function isBlockedDomain(host) {
  if (!host) return false;
  const hostLower = host.toLowerCase();
  return BLOCKED_DOMAINS.some(blocked => {
    return hostLower === blocked || hostLower.endsWith('.' + blocked);
  });
}

async function getisp() {
  try {
    const res = await axios.get('https://api.ip.sb/geoip', { headers: { 'User-Agent': 'Mozilla/5.0', timeout: 3000 }});
    const data = res.data;
    ISP = `${data.country_code}-${data.isp}`.replace(/ /g, '_');
  } catch (e) {
    try {
      const res2 = await axios.get('http://ip-api.com/json', { headers: { 'User-Agent': 'Mozilla/5.0', timeout: 3000 }});
      const data2 = res2.data;
      ISP = `${data2.countryCode}-${data2.org}`.replace(/ /g, '_');
    } catch (e2) {
      ISP = 'Unknown';
    }
  }
}

async function getip() {
  if (!DOMAIN || DOMAIN === 'your-domain.com') {
      try {
          const res = await axios.get('https://api-ipv4.ip.sb/ip', { timeout: 5000 });
          const ip = res.data.trim();
          CurrentDomain = ip, Tls = 'none', CurrentPort = PORT;
      } catch (e) {
          console.error('Failed to get IP', e.message);
          CurrentDomain = 'cahnge-your-domain.com', Tls = 'tls', CurrentPort = 443;
      }
  } else {
      CurrentDomain = DOMAIN, Tls = 'tls', CurrentPort = 443;
  }
}

// http route
const httpServer = http.createServer(async (req, res) => {
  if (req.url === '/') {
    const filePath = path.join(__dirname, 'index.html');
    fs.readFile(filePath, 'utf8', (err, content) => {
      if (err) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('Hello world!');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(content);
    });
    return;
  } else if (req.url === `/${SUB_PATH}`) {
    await getisp();await getip();
    const namePart = NAME ? `${NAME}-${ISP}` : ISP;
    const tlsParam = Tls === 'tls' ? 'tls' : 'none';
    const ssTlsParam = Tls === 'tls' ? 'tls;' : '';
    const vlsURL = `vless://${UUID}@${CurrentDomain}:${CurrentPort}?encryption=none&security=${tlsParam}&sni=${CurrentDomain}&fp=chrome&type=ws&host=${CurrentDomain}&path=%2F${WSPATH}#${namePart}`;
    const troURL = `trojan://${UUID}@${CurrentDomain}:${CurrentPort}?security=${tlsParam}&sni=${CurrentDomain}&fp=chrome&type=ws&host=${CurrentDomain}&path=%2F${WSPATH}#${namePart}`;
    const ssMethodPassword = Buffer.from(`none:${UUID}`).toString('base64');
    const ssURL = `ss://${ssMethodPassword}@${CurrentDomain}:${CurrentPort}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D${CurrentDomain};path%3D%2F${WSPATH};${ssTlsParam}sni%3D${CurrentDomain};skip-cert-verify%3Dtrue;mux%3D0#${namePart}`;
    const subscription = vlsURL + '\n' + troURL + '\n' + ssURL;
    const base64Content = Buffer.from(subscription).toString('base64');

    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(base64Content + '\n');
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found\n');
  }
});

// Custom DNS
function resolveHost(host) {
  return new Promise((resolve, reject) => {
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(host)) {
      resolve(host);
      return;
    }
    let attempts = 0;
    function tryNextDNS() {
      if (attempts >= DNS_SERVERS.length) {
        reject(new Error(`Failed to resolve ${host} with all DNS servers`));
        return;
      }
      const dnsServer = DNS_SERVERS[attempts];
      attempts++;
      const dnsQuery = `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`;
      axios.get(dnsQuery, {
        timeout: 5000,
        headers: {
          'Accept': 'application/dns-json'
        }
      })
        .then(response => {
          const data = response.data;
          if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
            const ip = data.Answer.find(record => record.type === 1);
            if (ip) {
              resolve(ip.data);
              return;
            }
          }
          tryNextDNS();
        })
        .catch(error => {
          tryNextDNS();
        });
    }

    tryNextDNS();
  });
}

// VLE-SS处理
function handleVlsConnection(ws, msg) {
  const [VERSION] = msg;
  const id = msg.slice(1, 17);
  if (!id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16))) return false;

  let i = msg.slice(17, 18).readUInt8() + 19;
  const port = msg.slice(i, i += 2).readUInt16BE(0);
  const ATYP = msg.slice(i, i += 1).readUInt8();
  const host = ATYP == 1 ? msg.slice(i, i += 4).join('.') :
    (ATYP == 2 ? new TextDecoder().decode(msg.slice(i + 1, i += 1 + msg.slice(i, i + 1).readUInt8())) :
      (ATYP == 3 ? msg.slice(i, i += 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':') : ''));

  if (isBlockedDomain(host)) {
    ws.close();
    return false;
  }
  ws.send(new Uint8Array([VERSION, 0]));
  const duplex = createWebSocketStream(ws);
  resolveHost(host)
    .then(resolvedIP => {
      net.connect({ host: resolvedIP, port }, function () {
        this.write(msg.slice(i));
        duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
      }).on('error', () => { });
    })
    .catch(error => {
      net.connect({ host, port }, function () {
        this.write(msg.slice(i));
        duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
      }).on('error', () => { });
    });

  return true;
}

// Tro-jan处理
function handleTrojConnection(ws, msg) {
  try {
    if (msg.length < 58) return false;
    const receivedPasswordHash = msg.slice(0, 56).toString();
    const possiblePasswords = [UUID];

    let matchedPassword = null;
    for (const pwd of possiblePasswords) {
      const hash = crypto.createHash('sha224').update(pwd).digest('hex');
      if (hash === receivedPasswordHash) {
        matchedPassword = pwd;
        break;
      }
    }

    if (!matchedPassword) return false;
    let offset = 56;
    if (msg[offset] === 0x0d && msg[offset + 1] === 0x0a) {
      offset += 2;
    }

    const cmd = msg[offset];
    if (cmd !== 0x01) return false;
    offset += 1;
    const atyp = msg[offset];
    offset += 1;
    let host, port;
    if (atyp === 0x01) {
      host = msg.slice(offset, offset + 4).join('.');
      offset += 4;
    } else if (atyp === 0x03) {
      const hostLen = msg[offset];
      offset += 1;
      host = msg.slice(offset, offset + hostLen).toString();
      offset += hostLen;
    } else if (atyp === 0x04) {
      host = msg.slice(offset, offset + 16).reduce((s, b, i, a) =>
        (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), [])
        .map(b => b.readUInt16BE(0).toString(16)).join(':');
      offset += 16;
    } else {
      return false;
    }

    port = msg.readUInt16BE(offset);
    offset += 2;

    if (offset < msg.length && msg[offset] === 0x0d && msg[offset + 1] === 0x0a) {
      offset += 2;
    }

    if (isBlockedDomain(host)) {
      ws.close();
      return false;
    }
    const duplex = createWebSocketStream(ws);
    resolveHost(host)
      .then(resolvedIP => {
        net.connect({ host: resolvedIP, port }, function () {
          if (offset < msg.length) {
            this.write(msg.slice(offset));
          }
          duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
        }).on('error', () => { });
      })
      .catch(error => {
        net.connect({ host, port }, function () {
          if (offset < msg.length) {
            this.write(msg.slice(offset));
          }
          duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
        }).on('error', () => { });
      });

    return true;
  } catch (error) {
    return false;
  }
}

// Ss处理
function handleSsConnection(ws, msg) {
  try {
    let offset = 0;
    const atyp = msg[offset];
    offset += 1;

    let host, port;
    if (atyp === 0x01) {
      host = msg.slice(offset, offset + 4).join('.');
      offset += 4;
    } else if (atyp === 0x03) {
      const hostLen = msg[offset];
      offset += 1;
      host = msg.slice(offset, offset + hostLen).toString();
      offset += hostLen;
    } else if (atyp === 0x04) {
      host = msg.slice(offset, offset + 16).reduce((s, b, i, a) =>
        (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), [])
        .map(b => b.readUInt16BE(0).toString(16)).join(':');
      offset += 16;
    } else {
      return false;
    }

    port = msg.readUInt16BE(offset);
    offset += 2;

    if (isBlockedDomain(host)) {
      ws.close();
      return false;
    }
    const duplex = createWebSocketStream(ws);
    resolveHost(host)
      .then(resolvedIP => {
        net.connect({ host: resolvedIP, port }, function () {
          if (offset < msg.length) {
            this.write(msg.slice(offset));
          }
          duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
        }).on('error', () => { });
      })
      .catch(error => {
        net.connect({ host, port }, function () {
          if (offset < msg.length) {
            this.write(msg.slice(offset));
          }
          duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
        }).on('error', () => { });
      });

    return true;
  } catch (error) {
    return false;
  }
}

// Ws handler
const wss = new WebSocket.Server({ server: httpServer });
wss.on('connection', (ws, req) => {
  const url = req.url || '';

  const expectedPath = `/${WSPATH}`;
  if (!url.startsWith(expectedPath)) {
    ws.close();
    return;
  }

  ws.once('message', msg => {
    // VLE-SS (version byte 0 + 16 bytes UUID)
    if (msg.length > 17 && msg[0] === 0) {
      const id = msg.slice(1, 17);
      const isVless = id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16));
      if (isVless) {
        if (!handleVlsConnection(ws, msg)) {
          ws.close();
        }
        return;
      }
    }
    // tro-jan (56 bytes SHA224 hash)
    if (msg.length >= 58) {
      if (handleTrojConnection(ws, msg)) {
        return;
      }
    }
    // SS (ATYP开头: 0x01, 0x03, 0x04)
    if (msg.length > 0 && (msg[0] === 0x01 || msg[0] === 0x03 || msg[0] === 0x04)) {
      if (handleSsConnection(ws, msg)) {
        return;
      }
    }

    ws.close();
  }).on('error', () => { });
});

const TLS_PORTS = new Set(['443', '8443', '2096', '2087', '2083', '2053']);
const NEZHA_AGENT_VERSION = 'node-agent-0.1.0';
const TASK_TYPE_HTTP_GET = 1;
const TASK_TYPE_ICMP_PING = 2;
const TASK_TYPE_TCP_PING = 3;
const TASK_TYPE_COMMAND = 4;
const TASK_TYPE_KEEPALIVE = 7;
const TASK_TYPE_TERMINAL_GRPC = 8;
const TASK_TYPE_FM = 11;
const TASK_TYPE_REPORT_CONFIG = 12;

const NEZHA_PROTO_SCHEMA = `
syntax = "proto3";
package proto;

message Host {
  string platform = 1;
  string platform_version = 2;
  repeated string cpu = 3;
  uint64 mem_total = 4;
  uint64 disk_total = 5;
  uint64 swap_total = 6;
  string arch = 7;
  string virtualization = 8;
  uint64 boot_time = 9;
  string version = 10;
  repeated string gpu = 11;
}

message State {
  message SensorTemperature {
    string name = 1;
    double temperature = 2;
  }
  double cpu = 1;
  uint64 mem_used = 2;
  uint64 swap_used = 3;
  uint64 disk_used = 4;
  uint64 net_in_transfer = 5;
  uint64 net_out_transfer = 6;
  uint64 net_in_speed = 7;
  uint64 net_out_speed = 8;
  uint64 uptime = 9;
  double load1 = 10;
  double load5 = 11;
  double load15 = 12;
  uint64 tcp_conn_count = 13;
  uint64 udp_conn_count = 14;
  uint64 process_count = 15;
  repeated SensorTemperature temperatures = 16;
  repeated double gpu = 17;
}

message Task {
  uint64 id = 1;
  uint64 type = 2;
  string data = 3;
}

message TaskResult {
  uint64 id = 1;
  uint64 type = 2;
  float delay = 3;
  string data = 4;
  bool successful = 5;
}

message Receipt {
  bool proced = 1;
}

message Uint64Receipt {
  uint64 data = 1;
}

message IOStreamData {
  bytes data = 1;
}

message GeoIP {
  bool use6 = 1;
  IP ip = 2;
  string country_code = 3;
  uint64 dashboard_boot_time = 4;
}

message IP {
  string ipv4 = 1;
  string ipv6 = 2;
}

service NezhaService {
  rpc ReportSystemInfo2(Host) returns (Uint64Receipt);
  rpc ReportGeoIP(GeoIP) returns (GeoIP);
  rpc ReportSystemState(stream State) returns (stream Receipt);
  rpc RequestTask(stream TaskResult) returns (stream Task);
  rpc IOStream(stream IOStreamData) returns (stream IOStreamData);
}
`;

const nezhaRoot = protobuf.parse(NEZHA_PROTO_SCHEMA, { keepCase: true }).root;
const nezhaTypes = {
  Host: nezhaRoot.lookupType('proto.Host'),
  State: nezhaRoot.lookupType('proto.State'),
  Task: nezhaRoot.lookupType('proto.Task'),
  TaskResult: nezhaRoot.lookupType('proto.TaskResult'),
  Receipt: nezhaRoot.lookupType('proto.Receipt'),
  Uint64Receipt: nezhaRoot.lookupType('proto.Uint64Receipt'),
  IOStreamData: nezhaRoot.lookupType('proto.IOStreamData'),
  GeoIP: nezhaRoot.lookupType('proto.GeoIP'),
  IP: nezhaRoot.lookupType('proto.IP')
};

function serializeMessage(type) {
  return value => type.encode(type.create(value || {})).finish();
}

function deserializeMessage(type) {
  return buffer => type.toObject(type.decode(buffer), {
    longs: Number,
    enums: Number,
    bytes: Buffer,
    defaults: true,
    arrays: true,
    objects: true
  });
}

const nezhaCodec = {
  serializeHost: serializeMessage(nezhaTypes.Host),
  deserializeUint64Receipt: deserializeMessage(nezhaTypes.Uint64Receipt),
  serializeGeoIP: serializeMessage(nezhaTypes.GeoIP),
  deserializeGeoIP: deserializeMessage(nezhaTypes.GeoIP),
  serializeState: serializeMessage(nezhaTypes.State),
  deserializeReceipt: deserializeMessage(nezhaTypes.Receipt),
  serializeTaskResult: serializeMessage(nezhaTypes.TaskResult),
  deserializeTask: deserializeMessage(nezhaTypes.Task),
  serializeIOStreamData: serializeMessage(nezhaTypes.IOStreamData),
  deserializeIOStreamData: deserializeMessage(nezhaTypes.IOStreamData)
};

function envBool(name, defaultValue = false) {
  const value = process.env[name];
  if (value === undefined || value === '') return defaultValue;
  return ['1', 'true', 'yes', 'on'].includes(String(value).trim().toLowerCase());
}

function envInt(name, defaultValue) {
  const value = process.env[name];
  if (value === undefined || value === '') return defaultValue;
  const parsed = parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : defaultValue;
}

function stripScheme(value) {
  let text = String(value || '').trim();
  if (text.includes('://')) text = text.split('://', 2)[1];
  return text.replace(/\/+$/g, '');
}

function extractPort(value) {
  const text = stripScheme(value);
  if (!text) return '';
  if (text.startsWith('[')) {
    const closing = text.indexOf(']');
    if (closing >= 0 && text[closing + 1] === ':') return text.slice(closing + 2);
    return '';
  }
  const first = text.indexOf(':');
  const last = text.lastIndexOf(':');
  if (first >= 0 && first === last && last < text.length - 1) return text.slice(last + 1);
  return '';
}

function hasExplicitPort(value) {
  return Boolean(extractPort(value));
}

function resolveNezhaTarget(server, port) {
  let host = stripScheme(server);
  if (!host) return '';
  if (hasExplicitPort(host)) return host;
  const resolvedPort = String(port || '').trim();
  if (!resolvedPort) return host;
  if (host.includes(':') && !host.startsWith('[')) host = `[${host}]`;
  return `${host}:${resolvedPort}`;
}

function parseHostPort(value) {
  const text = String(value || '').trim();
  if (text.startsWith('[')) {
    const closing = text.indexOf(']');
    if (closing < 0 || text[closing + 1] !== ':') throw new Error(`invalid host:port: ${value}`);
    return { host: text.slice(1, closing), port: parseInt(text.slice(closing + 2), 10) };
  }
  const split = text.lastIndexOf(':');
  if (split <= 0 || split === text.length - 1 || text.indexOf(':') !== split) throw new Error(`invalid host:port: ${value}`);
  return { host: text.slice(0, split), port: parseInt(text.slice(split + 1), 10) };
}

function isIpAddress(value) {
  return net.isIP(String(value || '')) !== 0;
}

function formatHostPort(host, port) {
  return String(host).includes(':') && !String(host).startsWith('[') ? `[${host}]:${port}` : `${host}:${port}`;
}

function parseDohEndpoints(value) {
  return String(value || '').split(',').map(v => v.trim()).filter(Boolean);
}

function safeUInt(value) {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) return 0;
  return Math.min(Math.floor(number), Number.MAX_SAFE_INTEGER);
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function createNezhaConfig() {
  if (!NEZHA_SERVER || !NEZHA_KEY) return null;
  const target = resolveNezhaTarget(NEZHA_SERVER, NEZHA_PORT);
  if (!target || !hasExplicitPort(target)) {
    console.error('NEZHA_SERVER must include a port, or NEZHA_PORT must be set');
    return null;
  }
  const port = extractPort(target);
  return {
    server: target,
    clientSecret: NEZHA_KEY,
    clientUuid: UUID,
    tls: envBool('NEZHA_TLS', TLS_PORTS.has(port)),
    reportDelay: Math.max(1, Math.min(4, envInt('NEZHA_REPORT_DELAY', 4))),
    ipReportPeriod: Math.max(30, envInt('NEZHA_IP_REPORT_PERIOD', 1800)),
    skipConnectionCount: envBool('NEZHA_SKIP_CONNECTION_COUNT', true),
    skipProcsCount: envBool('NEZHA_SKIP_PROCS_COUNT', true),
    disableCommandExecute: envBool('NEZHA_DISABLE_COMMAND_EXECUTE', false),
    disableSendQuery: envBool('NEZHA_DISABLE_SEND_QUERY', false),
    disableNat: envBool('NEZHA_DISABLE_NAT', true),
    useIpv6CountryCode: envBool('NEZHA_USE_IPV6_COUNTRY_CODE', false),
    dohEndpoints: parseDohEndpoints(NEZHA_DOH),
    toDict() {
      return {
        debug: false,
        server: this.server,
        client_secret: this.clientSecret,
        uuid: this.clientUuid,
        tls: this.tls,
        report_delay: this.reportDelay,
        ip_report_period: this.ipReportPeriod,
        skip_connection_count: this.skipConnectionCount,
        skip_procs_count: this.skipProcsCount,
        disable_command_execute: this.disableCommandExecute,
        disable_send_query: this.disableSendQuery,
        disable_nat: this.disableNat,
        gpu: false,
        temperature: false,
        disable_auto_update: true,
        disable_force_update: true,
        use_ipv6_country_code: this.useIpv6CountryCode,
        doh: this.dohEndpoints.join(',')
      };
    }
  };
}

class NezhaDohResolver {
  constructor(endpoints) {
    this.endpoints = endpoints || [];
  }

  async resolve(host) {
    if (!this.endpoints.length || isIpAddress(host)) return host;
    for (const recordType of ['A', 'AAAA']) {
      for (const endpoint of this.endpoints) {
        const resolved = await this.query(endpoint, host, recordType);
        if (resolved) return resolved;
      }
    }
    return host;
  }

  async query(endpoint, host, recordType) {
    try {
      const res = await axios.get(endpoint, {
        timeout: 5000,
        params: { name: host, type: recordType },
        headers: { Accept: 'application/dns-json', 'User-Agent': 'node-ws/1.0' },
        validateStatus: () => true
      });
      const data = res.data || {};
      if (res.status !== 200 || data.Status !== 0 || !Array.isArray(data.Answer)) return null;
      const expectedType = recordType === 'A' ? 1 : 28;
      const answer = data.Answer.find(item => item.type === expectedType && item.data);
      return answer ? answer.data : null;
    } catch (error) {
      return null;
    }
  }
}

class NezhaSystemMonitor {
  constructor(config) {
    this.config = config;
    this.bootTime = Math.floor(Date.now() / 1000 - os.uptime());
    this.netInTransfer = 0;
    this.netOutTransfer = 0;
    this.netInSpeed = 0;
    this.netOutSpeed = 0;
    this.lastNetSample = 0;
  }

  async collectHost() {
    const cpus = os.cpus() || [];
    const [memInfo, fsInfo] = await Promise.all([
      si.mem().catch(() => null),
      si.fsSize().catch(() => [])
    ]);
    const diskTotal = Array.isArray(fsInfo) ? fsInfo.reduce((sum, item) => sum + safeUInt(item.size), 0) : 0;
    return {
      platform: os.platform() || process.platform,
      platform_version: os.release() || '',
      cpu: cpus.length ? [cpus[0].model || os.arch()] : [os.arch()],
      mem_total: safeUInt(memInfo ? memInfo.total : os.totalmem()),
      disk_total: safeUInt(diskTotal),
      swap_total: safeUInt(memInfo ? memInfo.swaptotal : 0),
      arch: os.arch(),
      virtualization: '',
      boot_time: safeUInt(this.bootTime),
      version: NEZHA_AGENT_VERSION,
      gpu: []
    };
  }

  async collectState() {
    const [loadInfo, memInfo, fsInfo, netInfo, connInfo, procInfo] = await Promise.all([
      si.currentLoad().catch(() => null),
      si.mem().catch(() => null),
      si.fsSize().catch(() => []),
      si.networkStats().catch(() => []),
      this.config.skipConnectionCount ? Promise.resolve([]) : si.networkConnections().catch(() => []),
      this.config.skipProcsCount ? Promise.resolve(null) : si.processes().catch(() => null)
    ]);
    const diskUsed = Array.isArray(fsInfo) ? fsInfo.reduce((sum, item) => sum + safeUInt(item.used), 0) : 0;
    const netStats = this.networkStats(Array.isArray(netInfo) ? netInfo : []);
    const connStats = this.connectionStats(Array.isArray(connInfo) ? connInfo : []);
    const loadAvg = os.loadavg ? os.loadavg() : [0, 0, 0];
    return {
      cpu: Math.max(0, Number(loadInfo && loadInfo.currentLoad) || 0),
      mem_used: safeUInt(memInfo ? memInfo.total - memInfo.available : os.totalmem() - os.freemem()),
      swap_used: safeUInt(memInfo ? memInfo.swapused : 0),
      disk_used: safeUInt(diskUsed),
      net_in_transfer: safeUInt(netStats.inTransfer),
      net_out_transfer: safeUInt(netStats.outTransfer),
      net_in_speed: safeUInt(netStats.inSpeed),
      net_out_speed: safeUInt(netStats.outSpeed),
      uptime: safeUInt(os.uptime()),
      load1: Number(loadAvg[0]) || 0,
      load5: Number(loadAvg[1]) || 0,
      load15: Number(loadAvg[2]) || 0,
      tcp_conn_count: safeUInt(connStats.tcp),
      udp_conn_count: safeUInt(connStats.udp),
      process_count: safeUInt(procInfo && procInfo.all ? procInfo.all : 0),
      temperatures: [],
      gpu: []
    };
  }

  networkStats(stats) {
    const now = Math.floor(Date.now() / 1000);
    const inTransfer = stats.reduce((sum, item) => sum + safeUInt(item.rx_bytes), 0);
    const outTransfer = stats.reduce((sum, item) => sum + safeUInt(item.tx_bytes), 0);
    const inSec = stats.reduce((sum, item) => sum + safeUInt(item.rx_sec), 0);
    const outSec = stats.reduce((sum, item) => sum + safeUInt(item.tx_sec), 0);
    if (inSec || outSec) {
      this.netInSpeed = inSec;
      this.netOutSpeed = outSec;
    } else if (this.lastNetSample > 0 && now > this.lastNetSample) {
      const diff = now - this.lastNetSample;
      this.netInSpeed = Math.max(0, inTransfer - this.netInTransfer) / diff;
      this.netOutSpeed = Math.max(0, outTransfer - this.netOutTransfer) / diff;
    }
    this.netInTransfer = inTransfer;
    this.netOutTransfer = outTransfer;
    this.lastNetSample = now;
    return {
      inTransfer: this.netInTransfer,
      outTransfer: this.netOutTransfer,
      inSpeed: this.netInSpeed,
      outSpeed: this.netOutSpeed
    };
  }

  connectionStats(connections) {
    let tcp = 0, udp = 0;
    for (const conn of connections) {
      const proto = String(conn.protocol || conn.type || '').toLowerCase();
      if (proto.includes('tcp')) tcp++;
      else if (proto.includes('udp')) udp++;
    }
    return { tcp, udp };
  }
}

class NezhaTaskHandler {
  constructor(client) {
    this.client = client;
  }

  async handle(task) {
    const result = { id: task.id, type: task.type, delay: 0, data: '', successful: false };
    try {
      switch (Number(task.type)) {
        case TASK_TYPE_HTTP_GET:
          await this.httpGet(task, result);
          break;
        case TASK_TYPE_ICMP_PING:
          await this.icmpPing(task, result);
          break;
        case TASK_TYPE_TCP_PING:
          await this.tcpPing(task, result);
          break;
        case TASK_TYPE_COMMAND:
          await this.command(task, result);
          break;
        case TASK_TYPE_KEEPALIVE:
          result.successful = true;
          break;
        case TASK_TYPE_REPORT_CONFIG:
          result.data = JSON.stringify(this.client.config.toDict());
          result.successful = true;
          break;
        case TASK_TYPE_TERMINAL_GRPC:
          await this.client.startTerminal(task.data);
          return null;
        case TASK_TYPE_FM:
          await this.client.startFileManager(task.data);
          return null;
        default:
          result.data = `Unsupported Nezha task type: ${task.type}`;
      }
    } catch (error) {
      result.data = error && error.message ? error.message : String(error);
    }
    return result;
  }

  async httpGet(task, result) {
    if (this.client.config.disableSendQuery) {
      result.data = 'This server has disabled query sending';
      return;
    }
    const started = performance.now();
    const res = await axios.get(task.data, {
      timeout: 30000,
      maxRedirects: 0,
      validateStatus: () => true,
      headers: { 'User-Agent': 'nezha-agent/1.0' }
    });
    result.delay = performance.now() - started;
    if (res.status >= 200 && res.status <= 399) result.successful = true;
    else result.data = `HTTP error: ${res.status} ${res.statusText || ''}`.trim();
  }

  async tcpPing(task, result) {
    if (this.client.config.disableSendQuery) {
      result.data = 'This server has disabled query sending';
      return;
    }
    const { host, port } = parseHostPort(task.data);
    const started = performance.now();
    await new Promise((resolve, reject) => {
      const socket = net.connect({ host, port });
      const done = (error) => {
        socket.removeAllListeners();
        socket.destroy();
        error ? reject(error) : resolve();
      };
      socket.setTimeout(10000, () => done(new Error('tcp ping timeout')));
      socket.once('connect', () => done());
      socket.once('error', done);
    });
    result.delay = performance.now() - started;
    result.successful = true;
  }

  async icmpPing(task, result) {
    if (this.client.config.disableSendQuery) {
      result.data = 'This server has disabled query sending';
      return;
    }
    const isWindows = os.platform() === 'win32';
    const args = isWindows ? ['-n', '5', '-w', '4000', task.data] : ['-c', '5', '-W', '4', task.data];
    const started = performance.now();
    const output = await new Promise((resolve, reject) => {
      const proc = spawn('ping', args);
      let text = '';
      const timer = setTimeout(() => {
        proc.kill();
        reject(new Error('ping timeout'));
      }, 25000);
      proc.stdout.on('data', chunk => { text += chunk.toString(); });
      proc.stderr.on('data', chunk => { text += chunk.toString(); });
      proc.on('error', reject);
      proc.on('close', code => {
        clearTimeout(timer);
        if (code === 0) resolve(text);
        else reject(new Error(text.slice(-4096) || `ping exited with code ${code}`));
      });
    });
    result.delay = (performance.now() - started) / 5;
    result.data = output.slice(-2048);
    result.successful = true;
  }

  async command(task, result) {
    if (this.client.config.disableCommandExecute) {
      result.data = 'This agent has disabled command execution';
      return;
    }
    const started = performance.now();
    const output = await new Promise(resolve => {
      exec(task.data, { timeout: 7200000, maxBuffer: 2 * 1024 * 1024 }, (error, stdout, stderr) => {
        resolve({ error, text: `${stdout || ''}${stderr || ''}` });
      });
    });
    result.delay = (performance.now() - started) / 1000;
    result.data = output.text.slice(-2 * 1024 * 1024);
    if (!output.error) result.successful = true;
    else result.data = `${result.data}\n${output.error.message || output.error}`.trim();
  }
}

class NezhaIOStreamSession {
  constructor(client, streamId) {
    this.client = client;
    this.streamId = streamId;
    this.stream = null;
    this.closed = false;
    this.pending = [];
  }

  open() {
    this.stream = this.client.openIOStream();
    this.stream.write({ data: Buffer.concat([Buffer.from([0xff, 0x05, 0xff, 0x05]), Buffer.from(String(this.streamId))]) });
    for (const item of this.pending) this.stream.write(item);
    this.pending = [];
    return this.stream;
  }

  send(data) {
    if (this.closed) return false;
    const message = { data: Buffer.isBuffer(data) ? data : Buffer.from(data || '') };
    if (this.stream && !this.stream.destroyed && !this.stream.writableEnded) this.stream.write(message);
    else this.pending.push(message);
    return true;
  }

  keepalive() {
    return setInterval(() => this.send(Buffer.alloc(0)), 30000);
  }

  close() {
    this.closed = true;
    if (this.stream) {
      try { this.stream.end(); } catch (error) { }
      try { this.stream.destroy(); } catch (error) { }
    }
    this.pending = [];
  }
}

const FileManagerProtocol = {
  COMPLETE: Buffer.from('NZUP'),
  FILE: Buffer.from('NZTD'),
  FILE_NAME: Buffer.from('NZFN'),
  ERROR: Buffer.from('NERR'),
  listingHeader(dirPath) {
    const pathBytes = Buffer.from(dirPath);
    const header = Buffer.alloc(4);
    header.writeUInt32BE(pathBytes.length, 0);
    return Buffer.concat([this.FILE_NAME, header, pathBytes]);
  },
  appendName(payload, name, isDir) {
    const nameBytes = Buffer.from(name);
    return Buffer.concat([payload, Buffer.from([isDir ? 1 : 0, nameBytes.length & 0xff]), nameBytes]);
  },
  fileHeader(size) {
    const header = Buffer.alloc(8);
    header.writeBigUInt64BE(BigInt(Math.max(0, Number(size) || 0)), 0);
    return Buffer.concat([this.FILE, header]);
  },
  error(error) {
    const message = error && error.message ? error.message : String(error || 'unknown error');
    return Buffer.concat([this.ERROR, Buffer.from(message)]);
  }
};

class NezhaFileManagerSession {
  constructor(client, streamId) {
    this.session = new NezhaIOStreamSession(client, streamId);
    this.uploadFile = null;
    this.uploadSize = 0;
    this.uploadReceived = 0;
    this.uploadPath = null;
    this.keepaliveTimer = null;
  }

  run() {
    const stream = this.session.open();
    this.keepaliveTimer = this.session.keepalive();
    if (this.keepaliveTimer.unref) this.keepaliveTimer.unref();
    stream.on('data', message => this.handle(Buffer.from(message.data || [])).catch(error => {
      this.session.send(FileManagerProtocol.error(error));
    }));
    const cleanup = () => this.close();
    stream.once('error', cleanup);
    stream.once('end', cleanup);
    stream.once('close', cleanup);
  }

  async handle(payload) {
    if (!payload || !payload.length) return;
    if (this.uploadFile) {
      await this.acceptUploadChunk(payload);
      return;
    }
    const opcode = payload[0];
    if (opcode === 0) await this.listDir(this.pathFrom(payload, 1));
    else if (opcode === 1) await this.download(this.pathFrom(payload, 1));
    else if (opcode === 2) await this.beginUpload(payload);
    else this.session.send(FileManagerProtocol.error(`unknown file manager opcode: ${opcode}`));
  }

  async listDir(requested) {
    const fallback = os.homedir() || process.cwd();
    let directory = requested && fs.existsSync(requested) && fs.statSync(requested).isDirectory() ? requested : fallback;
    try {
      const displayPath = path.resolve(directory) + path.sep;
      let payload = FileManagerProtocol.listingHeader(displayPath);
      const entries = await fs.promises.readdir(directory, { withFileTypes: true });
      for (const entry of entries) payload = FileManagerProtocol.appendName(payload, entry.name, entry.isDirectory());
      this.session.send(payload);
    } catch (error) {
      this.session.send(FileManagerProtocol.error(error));
    }
  }

  async download(filePath) {
    if (!filePath) {
      this.session.send(FileManagerProtocol.error('path is empty'));
      return;
    }
    try {
      const stat = await fs.promises.stat(filePath);
      if (!stat.isFile()) {
        this.session.send(FileManagerProtocol.error('requested path is not a file'));
        return;
      }
      if (stat.size <= 0) {
        this.session.send(FileManagerProtocol.error('requested file is empty'));
        return;
      }
      this.session.send(FileManagerProtocol.fileHeader(stat.size));
      await new Promise((resolve, reject) => {
        const readable = fs.createReadStream(filePath, { highWaterMark: 1024 * 1024 });
        readable.on('data', chunk => this.session.send(chunk));
        readable.once('error', reject);
        readable.once('end', resolve);
      });
    } catch (error) {
      this.session.send(FileManagerProtocol.error(error));
    }
  }

  async beginUpload(payload) {
    if (payload.length < 9) {
      this.session.send(FileManagerProtocol.error('data is invalid'));
      return;
    }
    this.uploadSize = Number(payload.readBigUInt64BE(1));
    this.uploadReceived = 0;
    this.uploadPath = this.pathFrom(payload, 9);
    if (!this.uploadPath) {
      this.session.send(FileManagerProtocol.error('path is empty'));
      await this.resetUpload();
      return;
    }
    try {
      const parent = path.dirname(this.uploadPath);
      if (parent) await fs.promises.mkdir(parent, { recursive: true });
      this.uploadFile = fs.createWriteStream(this.uploadPath);
      if (this.uploadSize === 0) {
        await this.resetUpload();
        this.session.send(FileManagerProtocol.COMPLETE);
      }
    } catch (error) {
      this.session.send(FileManagerProtocol.error(error));
      await this.resetUpload();
    }
  }

  async acceptUploadChunk(payload) {
    try {
      await new Promise((resolve, reject) => this.uploadFile.write(payload, error => error ? reject(error) : resolve()));
      this.uploadReceived += payload.length;
      if (this.uploadReceived >= this.uploadSize) {
        await this.resetUpload();
        this.session.send(FileManagerProtocol.COMPLETE);
      }
    } catch (error) {
      this.session.send(FileManagerProtocol.error(error));
      await this.resetUpload();
    }
  }

  async resetUpload() {
    if (this.uploadFile) {
      await new Promise(resolve => this.uploadFile.end(resolve)).catch(() => { });
    }
    this.uploadFile = null;
    this.uploadSize = 0;
    this.uploadReceived = 0;
    this.uploadPath = null;
  }

  pathFrom(payload, offset) {
    if (payload.length <= offset) return null;
    const text = payload.slice(offset).toString();
    return text || null;
  }

  close() {
    if (this.keepaliveTimer) clearInterval(this.keepaliveTimer);
    this.resetUpload().catch(() => { });
    this.session.close();
  }
}

class NezhaTerminalSession {
  constructor(client, streamId) {
    this.session = new NezhaIOStreamSession(client, streamId);
    this.process = null;
    this.keepaliveTimer = null;
    this.commandBuffer = '';
  }

  run() {
    const stream = this.session.open();
    const isWindows = os.platform() === 'win32';
    const shell = isWindows ? 'powershell.exe' : (process.env.SHELL || '/bin/sh');
    const args = isWindows ? ['-NoLogo', '-NoProfile', '-NoExit', '-Command', '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8'] : ['-i'];
    this.process = spawn(shell, args, { stdio: 'pipe', env: { ...process.env, LANG: process.env.LANG || 'C.UTF-8', LC_ALL: process.env.LC_ALL || 'C.UTF-8', TERM: process.env.TERM || 'xterm-256color' } });
    this.keepaliveTimer = this.session.keepalive();
    if (this.keepaliveTimer.unref) this.keepaliveTimer.unref();

    this.process.stdout.on('data', data => this.sendTerminalOutput(data));
    this.process.stderr.on('data', data => this.sendTerminalOutput(data));
    this.process.once('error', error => this.session.send(Buffer.from(String(error.message || error))));
    this.process.once('close', () => this.close());

    stream.on('data', message => this.handleRemote(Buffer.from(message.data || [])));
    const cleanup = () => this.close();
    stream.once('error', cleanup);
    stream.once('end', cleanup);
    stream.once('close', cleanup);
  }

  handleRemote(payload) {
    if (!payload.length || !this.process || !this.process.stdin.writable) return;
    if (payload[0] === 1) return; // resize is only available with a PTY; plain shell fallback ignores it
    const frames = this.decodeTerminalFrames(payload);
    for (const frame of frames) this.writeTerminalData(frame);
  }

  decodeTerminalFrames(payload) {
    const frames = [];
    let offset = 0;
    while (offset < payload.length) {
      const opcode = payload[offset];
      if (opcode === 0 && offset + 1 < payload.length) {
        frames.push(payload.slice(offset + 1));
        break;
      }
      if ((opcode === 0 || opcode === 1) && offset + 5 <= payload.length) {
        const len = payload.readUInt32BE(offset + 1);
        if (len >= 0 && offset + 5 + len <= payload.length) {
          if (opcode === 0 && len > 0) frames.push(payload.slice(offset + 5, offset + 5 + len));
          offset += 5 + len;
          continue;
        }
      }
      frames.push(payload.slice(offset));
      break;
    }
    return frames;
  }

  sendTerminalOutput(data) {
    if (!data.length) return;
    const normalized = data.toString('utf8').replace(/([^\r])\n/g, '$1\r\n');
    this.session.send(Buffer.from(normalized, 'utf8'));
  }

  writeTerminalData(data) {
    if (!data.length) return;
    if (process.env.NEZHA_TERMINAL_DEBUG === 'true') {
      console.log('terminal input:', JSON.stringify(data.toString('utf8')), data.toString('hex'));
    }
    this.process.stdin.write(data);
  }

  close() {
    if (this.keepaliveTimer) clearInterval(this.keepaliveTimer);
    this.session.close();
    if (this.process && !this.process.killed) {
      try { this.process.kill(); } catch (error) { }
    }
    this.process = null;
  }
}

function streamIdFromTask(data, label) {
  try {
    const payload = JSON.parse(data || '{}');
    const streamId = payload.StreamID || payload.stream_id || payload.streamId;
    if (!streamId && process.env.NEZHA_DEBUG === 'true') console.error(`Nezha ${label} task missing StreamID`);
    return streamId || null;
  } catch (error) {
    if (process.env.NEZHA_DEBUG === 'true') console.error(`Invalid Nezha ${label} task payload`);
    return null;
  }
}

class EmbeddedNezhaClient {
  constructor(config) {
    this.config = config;
    this.monitor = new NezhaSystemMonitor(config);
    this.taskHandler = new NezhaTaskHandler(this);
    this.dohResolver = new NezhaDohResolver(config.dohEndpoints);
    this.client = null;
    this.running = false;
    this.loopPromise = null;
    this.activeStreams = new Set();
    this.timers = new Set();
    this.terminals = new Set();
    this.fileManagers = new Set();
    this.lastGeoQueryIp = '';
  }

  start() {
    if (this.loopPromise) return;
    this.running = true;
    this.loopPromise = this.runForever().catch(() => { });
  }

  async stop() {
    this.running = false;
    this.closeActive();
    if (this.client) {
      try { this.client.close(); } catch (error) { }
      this.client = null;
    }
    if (this.loopPromise) {
      await Promise.race([this.loopPromise.catch(() => { }), sleep(3000)]);
      this.loopPromise = null;
    }
  }

  async runForever() {
    while (this.running) {
      try {
        await this.runOnce();
      } catch (error) {
      }
      this.closeActive();
      if (this.client) {
        try { this.client.close(); } catch (error) { }
        this.client = null;
      }
      if (this.running) await sleep(10000);
    }
  }

  shortError(error) {
    if (!error) return 'unknown error';
    if (error.code !== undefined) return `${error.code}: ${error.details || error.message || ''}`;
    return error.message || String(error);
  }

  async runOnce() {
    this.client = await this.newChannel();
    await this.waitForReady(15000);
    await this.reportHost();

    const stateStream = this.startStateStream();
    const taskStream = this.startTaskStream();
    this.addTimer(setInterval(() => this.reportHost().catch(() => { }), 600000));
    this.addTimer(setInterval(() => this.reportGeoIP().catch(() => { }), this.config.ipReportPeriod * 1000));
    this.reportGeoIP().catch(() => { });

    await Promise.race([stateStream.done, taskStream.done]);
  }

  async newChannel() {
    const { host: originalHost, port: originalPort } = parseHostPort(this.config.server);
    const connectHost = await this.dohResolver.resolve(originalHost);
    const target = formatHostPort(connectHost, originalPort);
    const options = {
      'grpc.keepalive_time_ms': 30000,
      'grpc.keepalive_timeout_ms': 10000,
      'grpc.keepalive_permit_without_calls': 1,
      'grpc.max_receive_message_length': 16 * 1024 * 1024,
      'grpc.enable_http_proxy': 0
    };
    if (connectHost !== originalHost && !isIpAddress(originalHost)) {
      options['grpc.default_authority'] = originalHost;
      options['grpc.ssl_target_name_override'] = originalHost;
    }
    const credentials = this.config.tls ? grpc.credentials.createSsl() : grpc.credentials.createInsecure();
    return new grpc.Client(target, credentials, options);
  }

  waitForReady(timeoutMs) {
    return new Promise((resolve, reject) => {
      this.client.waitForReady(Date.now() + timeoutMs, error => error ? reject(error) : resolve());
    });
  }

  metadata() {
    const metadata = new grpc.Metadata();
    metadata.set('client_secret', this.config.clientSecret);
    metadata.set('client_uuid', this.config.clientUuid);
    return metadata;
  }

  unary(method, serialize, deserialize, request, timeoutMs = 10000) {
    return new Promise((resolve, reject) => {
      this.client.makeUnaryRequest(
        method,
        serialize,
        deserialize,
        request,
        this.metadata(),
        { deadline: Date.now() + timeoutMs },
        (error, response) => error ? reject(error) : resolve(response)
      );
    });
  }

  async reportHost() {
    const host = await this.monitor.collectHost();
    return this.unary('/proto.NezhaService/ReportSystemInfo2', nezhaCodec.serializeHost, nezhaCodec.deserializeUint64Receipt, host);
  }

  async reportGeoIP() {
    const geoip = await this.fetchGeoIP();
    if (!geoip) return null;
    return this.unary('/proto.NezhaService/ReportGeoIP', nezhaCodec.serializeGeoIP, nezhaCodec.deserializeGeoIP, geoip);
  }

  startStateStream() {
    const stream = this.client.makeBidiStreamRequest(
      '/proto.NezhaService/ReportSystemState',
      nezhaCodec.serializeState,
      nezhaCodec.deserializeReceipt,
      this.metadata()
    );
    this.activeStreams.add(stream);
    const writeState = async () => {
      if (!this.running || stream.destroyed || stream.writableEnded) return;
      try {
        stream.write(await this.monitor.collectState());
      } catch (error) {
        stream.destroy(error);
      }
    };
    writeState();
    const timer = setInterval(writeState, this.config.reportDelay * 1000);
    this.addTimer(timer);
    const done = this.streamDone(stream, 'state stream').finally(() => {
      clearInterval(timer);
      this.timers.delete(timer);
      this.activeStreams.delete(stream);
    });
    stream.on('data', () => { });
    return { stream, done };
  }

  startTaskStream() {
    const stream = this.client.makeBidiStreamRequest(
      '/proto.NezhaService/RequestTask',
      nezhaCodec.serializeTaskResult,
      nezhaCodec.deserializeTask,
      this.metadata()
    );
    this.activeStreams.add(stream);
    stream.on('data', task => {
      this.taskHandler.handle(task).then(result => {
        if (result && !stream.destroyed && !stream.writableEnded) stream.write(result);
      }).catch(error => {
        if (!stream.destroyed) stream.write({ id: task.id, type: task.type, data: error.message || String(error), successful: false });
      });
    });
    const done = this.streamDone(stream, 'task stream').finally(() => this.activeStreams.delete(stream));
    return { stream, done };
  }

  streamDone(stream, label) {
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (error) => {
        if (settled) return;
        settled = true;
        if (!this.running && !error) resolve();
        else reject(error || new Error(`${label} ended`));
      };
      stream.once('error', finish);
      stream.once('end', () => finish());
      stream.once('close', () => finish(this.running ? new Error(`${label} closed`) : null));
    });
  }

  addTimer(timer) {
    this.timers.add(timer);
    if (timer.unref) timer.unref();
  }

  closeActive() {
    for (const timer of this.timers) clearInterval(timer);
    this.timers.clear();
    for (const terminal of this.terminals) {
      try { terminal.close(); } catch (error) { }
    }
    this.terminals.clear();
    for (const fileManager of this.fileManagers) {
      try { fileManager.close(); } catch (error) { }
    }
    this.fileManagers.clear();
    for (const stream of this.activeStreams) {
      try { stream.destroy(); } catch (error) { }
    }
    this.activeStreams.clear();
  }

  openIOStream() {
    const stream = this.client.makeBidiStreamRequest(
      '/proto.NezhaService/IOStream',
      nezhaCodec.serializeIOStreamData,
      nezhaCodec.deserializeIOStreamData,
      this.metadata()
    );
    this.activeStreams.add(stream);
    const cleanup = () => this.activeStreams.delete(stream);
    stream.once('error', cleanup);
    stream.once('end', cleanup);
    stream.once('close', cleanup);
    return stream;
  }

  async startTerminal(data) {
    const streamId = streamIdFromTask(data, 'terminal');
    if (!streamId) return;
    const session = new NezhaTerminalSession(this, streamId);
    this.terminals.add(session);
    session.run();
  }

  async startFileManager(data) {
    const streamId = streamIdFromTask(data, 'file manager');
    if (!streamId) return;
    const session = new NezhaFileManagerSession(this, streamId);
    this.fileManagers.add(session);
    session.run();
  }

  async fetchGeoIP() {
    const endpoints = [
      'https://blog.cloudflare.com/cdn-cgi/trace',
      'https://developers.cloudflare.com/cdn-cgi/trace',
      'https://hostinger.com/cdn-cgi/trace',
      'https://ahrefs.com/cdn-cgi/trace'
    ];
    let ipv4 = '', ipv6 = '';
    for (const endpoint of endpoints) {
      try {
        const res = await axios.get(endpoint, {
          timeout: 20000,
          maxRedirects: 0,
          validateStatus: () => true,
          headers: { 'User-Agent': 'nezha-agent/1.0' }
        });
        const candidate = this.extractIp(typeof res.data === 'string' ? res.data : String(res.data || ''));
        if (!candidate || !isIpAddress(candidate)) continue;
        if (net.isIP(candidate) === 4 && !ipv4) ipv4 = candidate;
        else if (net.isIP(candidate) === 6 && !ipv6) ipv6 = candidate;
        if (ipv4 && ipv6) break;
      } catch (error) { }
    }
    const selected = this.config.useIpv6CountryCode && ipv6 ? ipv6 : (ipv4 || ipv6);
    if (!selected && this.lastGeoQueryIp === '') return null;
    if (selected === this.lastGeoQueryIp) return null;
    this.lastGeoQueryIp = selected;
    return {
      use6: this.config.useIpv6CountryCode,
      ip: { ipv4, ipv6 },
      country_code: '',
      dashboard_boot_time: 0
    };
  }

  extractIp(body) {
    for (const line of String(body || '').split(/\r?\n/)) {
      const text = line.trim();
      if (text.startsWith('ip=')) return text.slice(3).trim();
    }
    return String(body || '').trim();
  }
}

function createEmbeddedNezhaClient() {
  const config = createNezhaConfig();
  return config ? new EmbeddedNezhaClient(config) : null;
}

async function addAccessTask() {
  if (!AUTO_ACCESS) return;

  if (!DOMAIN) {
    return;
  }
  const fullURL = `https://${DOMAIN}/${SUB_PATH}`;
  try {
    const res = await axios.post("https://oooo.serv00.net/add-url", {
      url: fullURL
    }, {
      headers: {
        'Content-Type': 'application/json'
      }
    });
    console.log('Automatic Access Task added successfully');
  } catch (error) {
    // console.error('Error adding Task:', error.message);
  }
}

const embeddedNezhaClient = createEmbeddedNezhaClient();

httpServer.listen(PORT, () => {
  if (embeddedNezhaClient) embeddedNezhaClient.start();
  addAccessTask();
  console.log(`Server is running on port ${PORT}`);
});

async function shutdown() {
  if (embeddedNezhaClient) await embeddedNezhaClient.stop();
  httpServer.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}

process.once('SIGINT', shutdown);
process.once('SIGTERM', shutdown);

// hazzy.security_auditpro - index.js
const core = require("@actions/core");
const axios = require("axios");
const dns = require("dns").promises;
const whois = require("whois");
const util = require("util");
const net = require("net");
const { execSync } = require("child_process");

const lookupWhois = util.promisify(whois.lookup);

function cleanDomain(input) {
  try {
    if (/^https?:\/\//i.test(input)) return new URL(input).hostname.replace(/^www\./i, "");
    return input.replace(/^www\./i, "");
  } catch {
    return input.replace(/^www\./i, "");
  }
}

async function checkHTTPS(domain) {
  try {
    const start = Date.now();
    const r = await axios.get(`https://${domain}`, { timeout: 8000, validateStatus: () => true });
    const time = Date.now() - start;
    const headers = r.headers || {};
    return { status: r.status, time_ms: time, headers };
  } catch (e) {
    return { error: e.message };
  }
}

function parseSecurityHeaders(headers) {
  const s = {};
  s.hsts = Boolean(headers["strict-transport-security"]);
  s.csp = Boolean(headers["content-security-policy"] || headers["x-content-security-policy"]);
  s.x_frame = Boolean(headers["x-frame-options"]);
  s.x_xss = Boolean(headers["x-xss-protection"]);
  s.referrer = Boolean(headers["referrer-policy"]);
  s.permissions = Boolean(headers["permissions-policy"] || headers["feature-policy"]);
  s.cors = headers["access-control-allow-origin"] ? headers["access-control-allow-origin"] : null;
  return s;
}

async function sslInfo(domain) {
  try {
    // Use openssl on runner to get cert dates/issuer (if available)
    const cmd = `echo | openssl s_client -servername ${domain} -connect ${domain}:443 2>/dev/null | openssl x509 -noout -issuer -subject -dates`;
    const out = execSync(cmd, { stdio: ['pipe','pipe','ignore'], timeout: 8000 }).toString();
    const notBefore = (out.match(/notBefore=(.+)/) || [null, null])[1];
    const notAfter = (out.match(/notAfter=(.+)/) || [null, null])[1];
    const issuer = (out.match(/issuer=\/?(.+)/) || [null, null])[1];
    return { notBefore: notBefore ? new Date(notBefore).toISOString() : null, notAfter: notAfter ? new Date(notAfter).toISOString() : null, issuer: issuer ? issuer.trim() : null };
  } catch (e) {
    return { error: "openssl not available or connection failed" };
  }
}

async function simplePortCheck(host, port, timeout = 1500) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let status = "closed";
    socket.setTimeout(timeout);

    socket.on("connect", () => { status = "open"; socket.destroy(); });
    socket.on("timeout", () => { socket.destroy(); });
    socket.on("error", () => { /* ignore */ });
    socket.on("close", () => resolve({ port, status }));

    socket.connect(port, host);
  });
}

function detectWAF(headers) {
  const server = (headers.server || "").toLowerCase();
  const via = (headers.via || "").toLowerCase();
  const sc = (headers['server'] || '').toLowerCase();

  if (headers['cf-ray'] || headers['cf-request-id'] || server.includes('cloudflare')) return 'Cloudflare';
  if (headers['x-sucuri-bito'] || headers['x-sucuri-id']) return 'Sucuri';
  if (server.includes('akamai')) return 'Akamai';
  if (via.includes('incapsula') || headers['x-cdn']) return 'Incapsula';
  // fallback checks
  if (sc.includes('fastly')) return 'Fastly/WAF';
  return null;
}

async function run() {
  try {
    const raw = core.getInput("url", { required: true });
    const portsInput = core.getInput("ports") || "22,80,443,3306";
    const domain = cleanDomain(raw);
    core.info(`Auditing: ${domain}`);

    const report = { domain, timestamp: new Date().toISOString() };

    // DNS
    try {
      report.dns = {
        A: await dns.resolve4(domain).catch(()=>[]),
        AAAA: await dns.resolve6(domain).catch(()=>[]),
        MX: await dns.resolveMx(domain).catch(()=>[]),
        NS: await dns.resolveNs(domain).catch(()=>[])
      };
    } catch (e) {
      report.dns_error = e.message;
    }

    // WHOIS (non-blocking)
    try {
      report.whois_raw = await lookupWhois(domain);
    } catch (e) {
      report.whois_error = e.message;
    }

    // HTTPS & headers
    const httpsInfo = await checkHTTPS(domain);
    report.https = httpsInfo;
    if (httpsInfo && httpsInfo.headers) {
      report.security_headers = parseSecurityHeaders(httpsInfo.headers);
      report.waf = detectWAF(httpsInfo.headers);
    }

    // SSL details
    report.ssl = await sslInfo(domain);

    // Port checks (limited)
    const ips = report.dns && report.dns.A && report.dns.A.length ? report.dns.A : [];
    report.portscan = {};
    if (ips.length) {
      const ports = portsInput.split(",").map(p => parseInt(p.trim(),10)).filter(Boolean);
      for (const ip of ips.slice(0,2)) { // limit to first 2 IPs
        report.portscan[ip] = {};
        for (const p of ports) {
          try {
            const r = await simplePortCheck(ip, p);
            report.portscan[ip][p] = r.status;
          } catch (e) {
            report.portscan[ip][p] = "error";
          }
        }
      }
    }

    // Basic risk scoring
    let risk = 0;
    if (!report.https || report.https.status !== 200) risk += 10;
    if (report.ssl && report.ssl.notAfter) {
      const expires = new Date(report.ssl.notAfter);
      if ((expires - Date.now()) / (1000*60*60*24) < 14) risk += 10; // expiring soon
    }
    if (!report.security_headers || !report.security_headers.hsts) risk += 5;
    if (!report.security_headers || !report.security_headers.csp) risk += 5;
    if (report.portscan && Object.values(report.portscan).some(ipObj=>Object.values(ipObj).includes('open'))) risk += 10;

    report.risk_score = Math.min(100, risk * 5); // rough scale

    const out = JSON.stringify(report, null, 2);
    core.setOutput("report", out);
    core.info("Security audit complete.");
    core.info(out);

  } catch (err) {
    core.setFailed(String(err));
  }
}

run();

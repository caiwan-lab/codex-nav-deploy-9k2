/* ============================================================
   Codex 安装导航 · 邀请码系统服务器（Node.js 18+，零依赖，本地文件存储版）
   ------------------------------------------------------------
   学员端页面在 public/ 目录；
   邀请码数据存放在 data/codes.json（重启不丢失）；
   管理后台地址：/管理.html（用下方 adminPassword 登录）。
   ============================================================ */
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

/* ---------- 服务方配置区 ---------- */
const CONFIG = {
  adminPassword: process.env.ADMIN_PASSWORD || "codex-admin-2026", // 管理后台登录密码
  sessionSecret: process.env.SESSION_SECRET || "codex-nav-session-secret",
  sessionHours: 12, // 每次验证通过后，访问权保持的小时数
  codePrefix: "CX",  // 生成的邀请码前缀
};
/* ---------------------------------- */

const PORT = Number(process.env.PORT || 8081);
const HOST = process.env.HOST || "0.0.0.0";
const PUBLIC_DIR = path.join(__dirname, "public");
const DATA_DIR = path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "codes.json");

/* ---------- 本地 JSON 文件存储 ---------- */
let CODES = [];
try {
  if (fs.existsSync(DATA_FILE)) CODES = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  if (!Array.isArray(CODES)) CODES = [];
} catch (err) {
  console.error("读取数据文件失败，从空库启动:", err.message);
  CODES = [];
}
function saveCodes() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = DATA_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(CODES, null, 2));
  fs.renameSync(tmp, DATA_FILE); // 原子替换，避免写一半损坏
}
function findCode(code) {
  return CODES.find((r) => r.code === code) || null;
}

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".mp4": "video/mp4",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".json": "application/json",
};

/* ---------- 访问令牌（HMAC 签名） ---------- */
function b64url(buf) { return Buffer.from(buf).toString("base64url"); }
function sign(payload) {
  const body = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac("sha256", CONFIG.sessionSecret).update(body).digest("base64url");
  return `${body}.${sig}`;
}
function verifyToken(token) {
  if (typeof token !== "string" || !token.includes(".")) return null;
  const [body, sig] = token.split(".");
  const expect = crypto.createHmac("sha256", CONFIG.sessionSecret).update(body).digest("base64url");
  const a = Buffer.from(sig || ""), b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (!payload.exp || Date.now() >= payload.exp) return null;
    return payload;
  } catch { return null; }
}

/* ---------- 工具 ---------- */
function json(res, status, data) {
  const buf = Buffer.from(JSON.stringify(data));
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Content-Length": buf.length });
  res.end(buf);
}
function readBody(req) {
  return new Promise((resolve) => {
    let raw = "";
    req.on("data", (c) => { raw += c; if (raw.length > 1e6) req.destroy(); });
    req.on("end", () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch { resolve(null); } });
  });
}
function isAdmin(req) {
  const key = req.headers["x-admin-key"];
  return typeof key === "string" && key === CONFIG.adminPassword;
}
function randomCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let s = "";
  for (let i = 0; i < 6; i++) s += chars[crypto.randomInt(chars.length)];
  return `${CONFIG.codePrefix}${s}`;
}
function codeRow(row) {
  return {
    code: row.code, note: row.note, status: row.status,
    expires_at: row.expires_at, activated_at: row.activated_at,
    use_count: row.use_count, last_used_at: row.last_used_at,
    created_at: row.created_at,
  };
}

/* ---------- API ---------- */
async function api(req, res, pathname) {
  const body = await readBody(req);

  // 学员验证邀请码
  if (req.method === "POST" && pathname === "/api/verify") {
    const code = String((body && body.code) || "").trim().toUpperCase();
    if (!code) return json(res, 400, { ok: false, message: "请先输入邀请码。" });
    const row = findCode(code);
    if (!row) return json(res, 404, { ok: false, message: "邀请码不正确，请核对后重试。" });
    if (row.status !== "active") return json(res, 403, { ok: false, message: "邀请码已被停用，请联系老师。" });
    if (new Date(row.expires_at).getTime() <= Date.now())
      return json(res, 403, { ok: false, message: "邀请码已过期，请联系老师获取新的入口。" });
    const exp = Date.now() + CONFIG.sessionHours * 3600 * 1000;
    row.activated_at = row.activated_at || new Date().toISOString();
    row.use_count = (row.use_count || 0) + 1;
    row.last_used_at = new Date().toISOString();
    saveCodes();
    return json(res, 200, { ok: true, token: sign({ code, exp }), exp });
  }

  // 学员页面守卫校验令牌
  if (req.method === "POST" && pathname === "/api/check") {
    const payload = verifyToken(body && body.token);
    if (!payload) return json(res, 401, { ok: false });
    return json(res, 200, { ok: true });
  }

  /* ---------- 以下为管理接口 ---------- */
  if (!isAdmin(req)) return json(res, 401, { ok: false, message: "管理密码不正确。" });

  if (req.method === "GET" && pathname === "/api/admin/codes") {
    const rows = CODES.slice().sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")));
    return json(res, 200, { ok: true, codes: rows.map(codeRow) });
  }

  if (req.method === "POST" && pathname === "/api/admin/codes") {
    const note = String((body && body.note) || "").trim().slice(0, 100);
    const validDays = Math.min(Math.max(Number((body && body.validDays) || 30), 1), 3650);
    let code = "";
    for (let i = 0; i < 5; i++) {
      const candidate = randomCode();
      if (!findCode(candidate)) { code = candidate; break; }
    }
    if (!code) return json(res, 500, { ok: false, message: "生成邀请码失败，请重试。" });
    const row = {
      code, note, status: "active",
      expires_at: new Date(Date.now() + validDays * 24 * 3600 * 1000).toISOString(),
      activated_at: null, use_count: 0, last_used_at: null,
      created_at: new Date().toISOString(),
    };
    CODES.push(row);
    saveCodes();
    return json(res, 200, { ok: true, code: codeRow(row) });
  }

  if (req.method === "POST" && pathname === "/api/admin/status") {
    const code = String((body && body.code) || "").trim().toUpperCase();
    const row = findCode(code);
    if (!row) return json(res, 404, { ok: false, message: "邀请码不存在。" });
    row.status = body && body.status === "revoked" ? "revoked" : "active";
    saveCodes();
    return json(res, 200, { ok: true, code: codeRow(row) });
  }

  if (req.method === "POST" && pathname === "/api/admin/extend") {
    const code = String((body && body.code) || "").trim().toUpperCase();
    const days = Math.min(Math.max(Number((body && body.days) || 30), 1), 3650);
    const row = findCode(code);
    if (!row) return json(res, 404, { ok: false, message: "邀请码不存在。" });
    const base = Math.max(new Date(row.expires_at).getTime(), Date.now());
    row.expires_at = new Date(base + days * 24 * 3600 * 1000).toISOString();
    row.status = "active";
    saveCodes();
    return json(res, 200, { ok: true, code: codeRow(row) });
  }

  if (req.method === "POST" && pathname === "/api/admin/delete") {
    const code = String((body && body.code) || "").trim().toUpperCase();
    CODES = CODES.filter((r) => r.code !== code);
    saveCodes();
    return json(res, 200, { ok: true });
  }

  return json(res, 404, { ok: false, message: "接口不存在。" });
}

/* ---------- 静态文件（含 mp4 Range 支持） ---------- */
function serveStatic(req, res, pathname) {
  let rel = decodeURIComponent(pathname);
  if (rel === "/" || rel === "") rel = "/index.html";
  const filePath = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!filePath.startsWith(PUBLIC_DIR)) { res.writeHead(403); return res.end("Forbidden"); }
  fs.stat(filePath, (err, stat) => {
    if (err || !stat.isFile()) { res.writeHead(404); return res.end("Not Found"); }
    const type = MIME[path.extname(filePath).toLowerCase()] || "application/octet-stream";
    const range = req.headers.range;
    if (range) {
      const m = /bytes=(\d*)-(\d*)/.exec(range);
      const start = m && m[1] ? Number(m[1]) : 0;
      const end = m && m[2] ? Number(m[2]) : stat.size - 1;
      if (start >= stat.size || end >= stat.size) {
        return res.writeHead(416, { "Content-Range": `bytes */${stat.size}` }).end();
      }
      res.writeHead(206, {
        "Content-Type": type,
        "Content-Range": `bytes ${start}-${end}/${stat.size}`,
        "Accept-Ranges": "bytes",
        "Content-Length": end - start + 1,
      });
      fs.createReadStream(filePath, { start, end }).pipe(res);
    } else {
      res.writeHead(200, { "Content-Type": type, "Content-Length": stat.size, "Accept-Ranges": "bytes" });
      fs.createReadStream(filePath).pipe(res);
    }
  });
}

/* ---------- 主入口 ---------- */
const server = http.createServer(async (req, res) => {
  const pathname = new URL(req.url, `http://${req.headers.host || "localhost"}`).pathname;
  try {
    if (pathname.startsWith("/api/")) {
      await api(req, res, pathname);
    } else {
      serveStatic(req, res, pathname);
    }
  } catch (err) {
    console.error("Request error:", err);
    if (!res.headersSent) json(res, 500, { ok: false, message: "服务器内部错误。" });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Codex 安装导航邀请码系统已启动: http://${HOST}:${PORT}`);
});

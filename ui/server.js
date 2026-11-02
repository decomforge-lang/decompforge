const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const PORT = process.env.PORT ? Number(process.env.PORT) : 8787;
const ROOT = __dirname;
const BIN = resolveBin();

function resolveBin() {
  if (process.env.DECOMPFORGE_BIN && fs.existsSync(process.env.DECOMPFORGE_BIN)) return process.env.DECOMPFORGE_BIN;
  const candidates = [
    path.join(ROOT, '..', 'target', 'release', 'decompforge.exe'),
    path.join(ROOT, '..', 'target', 'debug', 'decompforge.exe'),
    path.join(ROOT, '..', 'target', 'release', 'decompforge'),
    path.join(ROOT, '..', 'target', 'debug', 'decompforge'),
  ];
  for (const c of candidates) if (fs.existsSync(c)) return c;
  return 'decompforge';
}

function runCli(args, opts = {}) {
  return new Promise((resolve) => {
    const child = spawn(BIN, args, { cwd: opts.cwd || process.cwd(), env: process.env });
    let stdout = '', stderr = '';
    child.stdout.on('data', d => { stdout += d; });
    child.stderr.on('data', d => { stderr += d; });
    child.on('close', code => resolve({ code, stdout, stderr }));
    child.on('error', err => resolve({ code: 127, stdout, stderr: String(err) }));
  });
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

function serveStatic(req, res) {
  let url = req.url.split('?')[0];
  if (url === '/') url = '/index.html';
  const filePath = path.join(ROOT, url);
  if (!filePath.startsWith(ROOT)) { res.writeHead(403); res.end(); return; }
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('not found'); return; }
    const ext = path.extname(filePath).toLowerCase();
    const types = { '.html':'text/html', '.js':'application/javascript', '.css':'text/css', '.json':'application/json', '.svg':'image/svg+xml', '.png':'image/png' };
    res.writeHead(200, { 'Content-Type': types[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

function detectFile(filePath) {
  const result = { path: filePath, size: 0, format: 'unknown', arch: null, bits: null, endian: null, platform: null, notes: [] };
  let buf;
  try {
    const st = fs.statSync(filePath);
    result.size = st.size;
    const fd = fs.openSync(filePath, 'r');
    const size = Math.min(st.size, 512);
    buf = Buffer.alloc(size);
    fs.readSync(fd, buf, 0, size, 0);
    fs.closeSync(fd);
  } catch (e) { result.notes.push('no se pudo leer: ' + e.message); return result; }

  // ELF
  if (buf.length >= 20 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
    result.format = 'elf';
    const eiClass = buf[4]; // 1=32, 2=64
    const eiData = buf[5]; // 1=little, 2=big
    result.bits = eiClass === 1 ? 32 : (eiClass === 2 ? 64 : null);
    result.endian = eiData === 1 ? 'little' : (eiData === 2 ? 'big' : null);
    // e_machine at offset 18 (16 for 32? actually e_machine at 18 for both)
    const machine = buf.readUInt16LE(18);
    const machines = { 8:'mips', 20:'powerpc', 40:'arm', 183:'aarch64', 62:'x86_64', 3:'x86', 21:'powerpc', 23:'spu' };
    result.arch = machines[machine] || ('machine_' + machine);
    // platform inference
    if (result.arch === 'mips' && result.endian === 'little' && result.bits === 32) result.platform = 'ps2 (R5900) o PSP';
    else if (result.arch === 'powerpc' && result.endian === 'big' && result.bits === 32) result.platform = 'ps3 (PPU 32 bits) o GameCube/Wii';
    else if (result.arch === 'powerpc' && result.endian === 'big' && result.bits === 64) result.platform = 'ps3 (PPU 64 bits)';
    else if (result.arch === 'aarch64') result.platform = 'nintendo switch (ARM64) o linux aarch64';
    else if (result.arch === 'arm') result.platform = 'nintendo 3ds / arm linux';
    else if (result.arch === 'x86_64') result.platform = 'pc (x86-64) linux/windows';
    else if (result.arch === 'spu') result.platform = 'ps3 (SPU) - no desensamblable';
    return result;
  }

  // PE (Windows)
  if (buf.length >= 2 && buf[0] === 0x4d && buf[1] === 0x5a) {
    result.format = 'pe';
    result.platform = 'windows (PE)';
    // read PE header offset at 0x3C
    if (buf.length >= 0x40) {
      const peOff = buf.readUInt32LE(0x3c);
      if (peOff + 6 <= buf.length) {
        const machine = buf.readUInt16LE(peOff + 4);
        const pem = { 0x8664:'x86_64', 0x014c:'x86 (i386)', 0x01c0:'arm', 0xaa64:'aarch64' };
        result.arch = pem[machine] || ('machine_' + machine.toString(16));
        result.bits = (machine === 0x8664 || machine === 0xaa64) ? 64 : 32;
        result.endian = 'little';
      }
    }
    return result;
  }

  // NSO (Switch)
  if (buf.length >= 4 && buf[0] === 0x4e && buf[1] === 0x53 && buf[2] === 0x4f && buf[3] === 0x30) {
    result.format = 'nso';
    result.arch = 'aarch64';
    result.bits = 64;
    result.endian = 'little';
    result.platform = 'nintendo switch (NSO)';
    return result;
  }

  // DOL (GameCube/Wii)
  if (buf.length >= 0x100) {
    // DOL header: text0 offset at 0x00, magic not present but structure: offsets are sane
    const textOff = buf.readUInt32BE(0x00);
    const textAddr = buf.readUInt32BE(0x48);
    if (textOff === 0x100 && textAddr >= 0x80000000) {
      result.format = 'dol';
      result.arch = 'powerpc';
      result.bits = 32;
      result.endian = 'big';
      result.platform = 'nintendo gamecube / wii (DOL)';
      return result;
    }
  }

  // Mach-O (macOS/iOS)
  const magic = buf.readUInt32LE(0);
  if (magic === 0xfeedface || magic === 0xfeedfacf || magic === 0xcefaedfe || magic === 0xcffaedfe) {
    result.format = 'mach-o';
    result.platform = 'macos / ios';
    result.endian = (magic === 0xcefaedfe || magic === 0xcffaedfe) ? 'big' : 'little';
    result.bits = (magic === 0xfeedfacf || magic === 0xcffaedfe) ? 64 : 32;
    return result;
  }

  // Raw / unknown: try extension
  const ext = path.extname(filePath).toLowerCase();
  const extMap = { '.exe':'windows (PE?)', '.elf':'elf', '.bin':'binario plano', '.rom':'rom plana', '.iso':'imagen de disco', '.nso':'nintendo switch', '.dol':'gamecube/wii' };
  if (extMap[ext]) { result.platform = extMap[ext]; result.notes.push('detectado por extension'); }
  return result;
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > 10 * 1024 * 1024) reject(new Error('too large')); });
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}

async function handleApi(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const pathname = url.pathname;

  if (req.method === 'GET' && pathname === '/api/bin') {
    return sendJson(res, 200, { bin: BIN });
  }

  if (req.method === 'GET' && pathname === '/api/detect') {
    const filePath = url.searchParams.get('path');
    if (!filePath) return sendJson(res, 400, { error: 'falta path' });
    return sendJson(res, 200, detectFile(filePath));
  }

  if (req.method === 'GET' && pathname === '/api/projects') {
    const dir = url.searchParams.get('dir') || process.cwd();
    let files = [];
    try { files = fs.readdirSync(dir).filter(f => f.endsWith('.dfproj')).map(f => path.join(dir, f)); } catch (e) {}
    return sendJson(res, 200, { dir, files });
  }

  if (req.method === 'POST') {
    let body;
    try { body = await parseBody(req); } catch (e) { return sendJson(res, 400, { error: String(e) }); }

    if (pathname === '/api/init') {
      const args = ['init', body.name || 'demo'];
      if (body.platform) args.push('--platform', body.platform);
      if (body.dir) args.push('--dir', body.dir);
      if (body.sample) args.push('--sample');
      const r = await runCli(args);
      return sendJson(res, r.code === 0 ? 200 : 400, r);
    }

    if (pathname === '/api/load') {
      const args = ['load', body.binary, '--project', body.project];
      if (body.arch) args.push('--arch', body.arch);
      if (body.endian) args.push('--endian', body.endian);
      if (body.base) args.push('--base', body.base);
      if (body.noAnalyze) args.push('--no-analyze');
      const r = await runCli(args);
      return sendJson(res, r.code === 0 ? 200 : 400, r);
    }

    if (pathname === '/api/analyze') {
      const r = await runCli(['analyze', body.binary, '--project', body.project]);
      return sendJson(res, r.code === 0 ? 200 : 400, r);
    }

    if (pathname === '/api/info') {
      const r = await runCli(['info', '--project', body.project, '--json']);
      let info = null;
      try { info = JSON.parse(r.stdout); } catch (e) {}
      return sendJson(res, r.code === 0 ? 200 : 400, { ...r, info });
    }

    if (pathname === '/api/name') {
      const args = ['name', body.binary, '--project', body.project];
      if (body.config) args.push('--config', body.config);
      if (body.batch) args.push('--batch');
      if (body.limit) args.push('--limit', String(body.limit));
      if (body.function) args.push('--function', body.function);
      if (body.force) args.push('--force');
      if (body.json) args.push('--json');
      const r = await runCli(args);
      let data = null;
      try { data = JSON.parse(r.stdout); } catch (e) {}
      return sendJson(res, r.code === 0 ? 200 : 400, { ...r, data });
    }

    if (pathname === '/api/name-list') {
      const args = ['name', 'list', '--project', body.project];
      if (body.state) args.push('--state', body.state);
      if (body.function) args.push('--function', body.function);
      args.push('--json');
      const r = await runCli(args);
      let data = null;
      try { data = JSON.parse(r.stdout); } catch (e) {}
      return sendJson(res, r.code === 0 ? 200 : 400, { ...r, data });
    }

    if (pathname === '/api/name-accept') {
      const args = ['name', 'accept', String(body.id), '--project', body.project];
      if (body.force) args.push('--force');
      const r = await runCli(args);
      return sendJson(res, r.code === 0 ? 200 : 400, r);
    }

    if (pathname === '/api/name-reject') {
      const r = await runCli(['name', 'reject', String(body.id), '--project', body.project]);
      return sendJson(res, r.code === 0 ? 200 : 400, r);
    }

    if (pathname === '/api/name-config') {
      const r = await runCli(['name', 'config']);
      return sendJson(res, r.code === 0 ? 200 : 400, r);
    }

    if (pathname === '/api/export') {
      const args = ['export', '--format', body.format || 'json', '--project', body.project];
      if (body.output) args.push('--output', body.output);
      const r = await runCli(args);
      return sendJson(res, r.code === 0 ? 200 : 400, r);
    }

    if (pathname === '/api/apply') {
      const r = await runCli(['apply', body.file, '--project', body.project]);
      return sendJson(res, r.code === 0 ? 200 : 400, r);
    }
  }

  res.writeHead(404); res.end('not found');
}

const server = http.createServer(async (req, res) => {
  if (req.url.startsWith('/api/')) {
    try { await handleApi(req, res); } catch (e) { sendJson(res, 500, { error: String(e) }); }
  } else {
    serveStatic(req, res);
  }
});

server.listen(PORT, () => {
  console.log(`DecompForge UI: http://localhost:${PORT}`);
  console.log(`Binario: ${BIN}`);
});
// CMD Kế toán — nút "Phát hành bản cập nhật" (Q33, 2.6.0; chủ 11/11/2026: "Đồng ý để khóa cập nhật vĩnh viễn lưu trữ trừ khi có bản vá mới nhất thì tự
// xóa bản cũ"). Chạy trong GitHub Actions của KHO CÔNG KHAI dmbmagician/cmd-ketoan-ban-cai (.github/workflows/phat-hanh-ban-cap-nhat.yml và
// cap-nhat-may-chu-key.yml). Bản gốc + test: kho mã nguồn tools/cmd-license-tools/kho-cong-khai/.github/cmd/phat-hanh.mjs — sửa ở đó rồi chép lại.
// Chỉ dùng thư viện có sẵn của Node (≥ 20). KHÔNG chạy mã nào của kho mã nguồn: bộ cài chỉ là dữ liệu (tải, băm, đưa lên).
//   node phat-hanh.mjs phat-hanh — tìm bộ cài của bản dựng CI đã đạt → đối chiếu SHA-256 với nhật ký lượt dựng → đưa lên Releases của kho này (bản thử)
//                                  → tải lại từ địa chỉ công khai kiểm SHA-256 → ký bản kê (CMD_UPDATE_KEY) → báo máy chủ key (CMD_PHAT_HANH_TOKEN) →
//                                  đánh dấu Latest → xóa bản cũ, giữ 1 bản liền trước (máy chủ chọn).
//   node phat-hanh.mjs tim       — chỉ tìm commit của bản dựng (cho quy trình "Cập nhật máy chủ key"); ghi sha=… vào GITHUB_OUTPUT.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { Readable, Transform, Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';

export const NGUON = 'dmbmagician/CMD-PHAN-MEM-KE-TOAN';
export const MAY_CHU = 'https://cmdketoan.ducmb97.workers.dev';
export const KHOA_CONG_KHAI_U1 = 'fdpIsbUVKkvXW1lXhAxmhSfGcTiEQC+M8j3P7oNT/rQ=';
export const QUY_TRINH_CI = 'windows-package.yml';
export const MAC_DINH_TU_BAN = '2.6.0';
export const MAX_BYTES = 1610612736; // như máy khách (desktop/license/update.cjs)
export const SO_TAY_MAX = 64 * 1048576;
const NHAT_KY_MAX = 64 * 1048576;
const API = 'https://api.github.com';
const SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const BAN_RE = /^\d{1,4}\.\d{1,4}\.\d{1,6}$/;
const VERSION_RE = /^\d{1,4}\.\d{1,4}\.\d{1,6}(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?$/;
const loi = (msg) => new Error(msg);
const mb = (n) => (Number(n) / 1048576).toFixed(1).replace('.', ',');
// Lời của GitHub / máy chủ đưa vào thông báo: một dòng, che chuỗi dài (mã truy cập không bao giờ lọt ra nhật ký công khai).
const gon = (s) => String(s || '').replace(/[A-Za-z0-9+/=_-]{32,}/g, '…').replace(/\s+/g, ' ').trim().slice(0, 300);

// Như format.compareVersions của CMD (x.y.z[-nhãn]; bản có nhãn nhỏ hơn bản không nhãn) — test so với bản gốc.
export function compareVersions(a, b) {
  const parse = (v) => {
    const s = String(v ?? '').trim().replace(/^[vV]/, '').split('+')[0];
    const i = s.indexOf('-');
    const core = (i >= 0 ? s.slice(0, i) : s).split('.').map((x) => (Number.isFinite(Number(x)) ? Number(x) : 0));
    while (core.length < 3) core.push(0);
    const preStr = i >= 0 ? s.slice(i + 1) : '';
    return { core, pre: preStr ? preStr.split('.') : [] };
  };
  const va = parse(a), vb = parse(b);
  for (let i = 0; i < Math.max(va.core.length, vb.core.length); i++) {
    const na = va.core[i] ?? 0, nb = vb.core[i] ?? 0;
    if (na !== nb) return na < nb ? -1 : 1;
  }
  if (!va.pre.length && !vb.pre.length) return 0;
  if (!va.pre.length) return 1;
  if (!vb.pre.length) return -1;
  for (let i = 0; i < Math.max(va.pre.length, vb.pre.length); i++) {
    const ia = va.pre[i], ib = vb.pre[i];
    if (ia === undefined) return -1;
    if (ib === undefined) return 1;
    const da = /^\d+$/.test(ia), db = /^\d+$/.test(ib);
    if (da && db) {
      if (Number(ia) !== Number(ib)) return Number(ia) < Number(ib) ? -1 : 1;
    } else if (da !== db) return da ? -1 : 1;
    else if (ia !== ib) return ia < ib ? -1 : 1;
  }
  return 0;
}

export function kiemBan(v) {
  const ban = String(v ?? '').trim().replace(/^[vV]/, '');
  if (!BAN_RE.test(ban)) throw loi('Số bản phải dạng x.y.z (ví dụ 2.6.1) — bản phát hành cho khách không có đuôi -alpha.');
  return ban;
}
export function kiemCommit(v) {
  const c = String(v ?? '').trim().toLowerCase();
  if (c && !/^[0-9a-f]{7,40}$/.test(c)) throw loi('Mã commit phải là 7 – 40 ký tự 0-9 a-f (ví dụ 801a9a0).');
  return c;
}
export function kiemDauVao(env) {
  const ban = kiemBan(env.BAN);
  const commit = kiemCommit(env.COMMIT);
  const tuBan = String(env.TU_BAN ?? '').trim() || MAC_DINH_TU_BAN;
  if (!VERSION_RE.test(tuBan)) throw loi('"Từ bản" phải dạng x.y.z hoặc x.y.z-nhãn.');
  if (compareVersions(tuBan, ban) > 0) throw loi(`"Từ bản" (${tuBan}) lớn hơn số bản phát hành (${ban}).`);
  // eslint-disable-next-line no-control-regex
  const ghiChu = String(env.GHI_CHU ?? '').replace(/[\u0000-\u001f\u007f\s]+/g, ' ').trim().slice(0, 500);
  // Rà độc lập R12-N3 (2.6.0): bỏ ô "Bản vá an toàn" — cờ bản vá lấy từ build-info của lượt dựng (CI chưa dựng bản vá an toàn: luôn false). Trước sửa: bản kê ký
  // safetyPatch:true trong khi bộ cài có build-info safetyPatch:false → khách hết hạn cập nhật được cài rồi bị khóa CHỈ XEM.
  return { ban, commit, tuBan, ghiChu };
}

// Khóa riêng cập nhật (nội dung tệp update-u1.private.txt: PKCS8 48 byte, hoặc hạt 32 byte, dạng base64) — phải cùng cặp với khóa công khai CMD đang gắn.
export function khoaRieng(b64, pubB64 = KHOA_CONG_KHAI_U1) {
  const raw = Buffer.from(String(b64 ?? '').replace(/\s+/g, ''), 'base64');
  const der = raw.length === 48 ? raw : raw.length === 32 ? Buffer.concat([PKCS8, raw]) : null;
  let key = null;
  try {
    if (der) key = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  } catch {
    key = null;
  }
  if (!key || key.asymmetricKeyType !== 'ed25519') throw loi('CMD_UPDATE_KEY không phải khóa riêng Ed25519 — dán đúng nội dung tệp update-u1.private.txt.');
  const pub = crypto.createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64');
  if (pub !== pubB64) throw loi('CMD_UPDATE_KEY không cùng cặp với khóa công khai cập nhật CMD đang gắn (u1) — dán đúng nội dung tệp update-u1.private.txt.');
  return key;
}

// Bản kê CMDUPD1 — đúng trường, thứ tự và cách mã như app/shared/license (format.orderPayload, crypto.signCompact); tự kiểm bằng khóa công khai u1.
export function kyBanKe(p, key, pubB64 = KHOA_CONG_KHAI_U1) {
  const ordered = {
    v: 1,
    typ: 'cmd-update',
    channel: 'stable',
    version: String(p.version),
    build: String(p.build),
    safetyPatch: Boolean(p.safetyPatch),
    dataVersion: 3,
    url: String(p.url),
    size: Number(p.size),
    sha256: String(p.sha256),
    notes: String(p.notes ?? ''),
    minFrom: String(p.minFrom),
    publishedAt: String(p.publishedAt),
  };
  if (!BAN_RE.test(ordered.version) || !VERSION_RE.test(ordered.minFrom) || !/^\d{4}-\d{2}-\d{2}$/.test(ordered.build)) throw loi('Bản kê thiếu / sai trường.');
  if (!Number.isInteger(ordered.size) || ordered.size <= 0 || !/^[0-9a-f]{64}$/.test(ordered.sha256)) throw loi('Bản kê thiếu / sai trường.');
  const bytes = Buffer.from(JSON.stringify(ordered), 'utf8');
  const sig = crypto.sign(null, bytes, key);
  const pub = crypto.createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(pubB64, 'base64')]), format: 'der', type: 'spki' });
  if (!crypto.verify(null, bytes, pub, sig)) throw loi('Bản kê vừa ký không kiểm được bằng khóa công khai u1.');
  return `CMDUPD1.${bytes.toString('base64url')}.${sig.toString('base64url')}.u1`;
}
const payloadOf = (compact) => JSON.parse(Buffer.from(String(compact).split('.')[1] || '', 'base64url').toString('utf8'));

// GitHub REST — mã truy cập chỉ đi trong tiêu đề; lỗi trả về một dòng gọn.
export function taoGithub(token, fetchFn) {
  const headers = (extra = {}) => ({
    authorization: 'Bearer ' + token,
    accept: 'application/vnd.github+json',
    'x-github-api-version': '2022-11-28',
    'user-agent': 'cmd-phat-hanh',
    ...extra,
  });
  async function call(method, url, { body, okNull = false, extra } = {}) {
    const res = await fetchFn(url.startsWith('https://') ? url : API + url, {
      method,
      headers: headers(body !== undefined ? { 'content-type': 'application/json', ...extra } : extra),
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (okNull && res.status === 404) return null;
    if (res.status === 204) return {};
    let j = null;
    try {
      j = await res.json();
    } catch {
      j = null;
    }
    if (!res.ok) {
      const hint = res.status === 401 || res.status === 403 ? ' — kiểm mã truy cập / quyền của nó.' : '';
      throw loi(`GitHub trả lỗi ${res.status} khi ${method} ${url.split('?')[0]}: ${gon(j?.message)}${hint}`);
    }
    return j;
  }
  async function pages(url, key) {
    const out = [];
    for (let page = 1; page <= 10; page++) {
      const j = await call('GET', `${url}${url.includes('?') ? '&' : '?'}per_page=100&page=${page}`);
      const items = key ? j?.[key] || [] : j || [];
      out.push(...items);
      if (items.length < 100) break;
    }
    return out;
  }
  // Tải tệp qua API: GitHub trả 302 tới máy lưu tệp (đi tiếp KHÔNG kèm mã truy cập) hoặc trả thẳng nội dung (200).
  async function taiQuaApi(url, file, { accept, max } = {}) {
    const res = await fetchFn(API + url, { headers: headers(accept ? { accept } : {}), redirect: 'manual' });
    const loc = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && loc) return taiVe(fetchFn, loc, file, { max });
    if (res.status === 200) return luuPhanHoi(res, url, file, { max });
    throw loi(`GitHub không cho tải ${url.split('?')[0]} (${res.status}) — kiểm quyền Contents / Actions của NGUON_TOKEN.`);
  }
  // Nhật ký một lượt chạy (chữ thường): GitHub trả 302 tới máy lưu (đi tiếp KHÔNG kèm mã truy cập); 404 / 410 = nhật ký đã hết hạn → null.
  async function docNhatKy(url, { max = NHAT_KY_MAX } = {}) {
    const res = await fetchFn(API + url, { headers: headers(), redirect: 'manual' });
    const loc = res.headers.get('location');
    const r = res.status >= 300 && res.status < 400 && loc ? await fetchFn(loc, { redirect: 'follow' }) : res;
    if (r.status === 404 || r.status === 410) return null;
    if (!r.ok || !r.body) throw loi(`GitHub không cho đọc nhật ký ${url.split('?')[0]} (${r.status}) — kiểm quyền Actions của NGUON_TOKEN.`);
    const parts = [];
    let size = 0;
    for await (const c of Readable.fromWeb(r.body)) {
      size += c.length;
      if (size > max) throw loi('Nhật ký lượt dựng quá lớn.');
      parts.push(c);
    }
    return Buffer.concat(parts).toString('utf8');
  }
  return { call, pages, taiQuaApi, docNhatKy, token };
}

// Tìm bộ cài của bản dựng CI: (1) bản thử ci/<số bản>-<commit7> có tệp CMD-Ke-Toan-<số bản>-Setup.exe; (2) artifact CMD-Ke-Toan-<số bản> chưa hết hạn.
// Nhiều bản dựng cùng số bản → phải gõ mã commit. Lượt dựng CI (windows-package.yml) của commit đó phải ĐẠT.
export async function timBanDung(src, { ban, commit = '', nguon = NGUON }) {
  const setupName = `CMD-Ke-Toan-${ban}-Setup.exe`;
  const cands = new Map();
  const tagRe = new RegExp(`^ci/${ban.replace(/\./g, '\\.')}-([0-9a-f]{7})$`);
  for (const r of await src.pages(`/repos/${nguon}/releases`)) {
    const m = tagRe.exec(String(r?.tag_name || ''));
    if (!m) continue;
    const asset = (r.assets || []).find((a) => a && a.name === setupName && a.state === 'uploaded');
    if (!asset) continue;
    let sha = String(r.target_commitish || '').toLowerCase();
    if (!/^[0-9a-f]{40}$/.test(sha) || !sha.startsWith(m[1])) {
      const c = await src.call('GET', `/repos/${nguon}/commits/${m[1]}`, { okNull: true });
      sha = String(c?.sha || '').toLowerCase();
      if (!/^[0-9a-f]{40}$/.test(sha) || !sha.startsWith(m[1])) continue;
    }
    const soTay = (r.assets || []).find((a) => a && a.name === 'So-tay-CMD-Ke-Toan.html' && a.state === 'uploaded');
    cands.set(sha, { sha, nguon: 'release', tag: m[1], assetId: asset.id, soTayId: soTay ? soTay.id : null, at: String(r.created_at || '') });
  }
  const arts = await src.pages(`/repos/${nguon}/actions/artifacts?name=${encodeURIComponent('CMD-Ke-Toan-' + ban)}`, 'artifacts');
  for (const a of arts) {
    const sha = String(a?.workflow_run?.head_sha || '').toLowerCase();
    if (a?.expired || !/^[0-9a-f]{40}$/.test(sha) || cands.has(sha)) continue;
    cands.set(sha, { sha, nguon: 'artifact', artifactId: a.id, at: String(a.created_at || '') });
  }
  let list = [...cands.values()];
  if (commit) list = list.filter((c) => c.sha.startsWith(commit));
  if (!list.length) {
    throw loi(
      `Không tìm thấy bộ cài của bản ${ban}${commit ? ' commit ' + commit : ''} — đẩy commit có [winbuild] và chờ quy trình "Windows package (CI)" chạy xong` +
        ' (bộ cài lưu ở Releases "ci/<số bản>-<commit>" hoặc artifact giữ 2 ngày).'
    );
  }
  if (list.length > 1) {
    const ds = list.map((c) => `${c.sha.slice(0, 7)} (${c.at.slice(0, 10)})`).join(', ');
    throw loi(`Có ${list.length} bản dựng ${ban}: ${ds} — gõ mã commit của bản bạn đã thử vào ô "commit" rồi bấm lại.`);
  }
  const bd = list[0];
  const runs = await src.call('GET', `/repos/${nguon}/actions/workflows/${QUY_TRINH_CI}/runs?head_sha=${bd.sha}&status=success&per_page=10`);
  const ok = (runs?.workflow_runs || []).filter((r) => r && Number.isSafeInteger(Number(r.id)) && (!r.head_sha || String(r.head_sha).toLowerCase() === bd.sha) && (!r.conclusion || r.conclusion === 'success'));
  if (!ok.length) {
    throw loi(`Lượt dựng CI của commit ${bd.sha.slice(0, 7)} chưa đạt (đang chạy / lỗi / chưa chạy) — chỉ phát hành bản dựng đã đạt.`);
  }
  return { ...bd, setupName, runIds: ok.map((r) => Number(r.id)) };
}

// Rà độc lập R12-V1 (2.6.0): bộ cài phải ĐÚNG tệp do lượt CI đã đạt của commit dựng ra — bước "Customer installer" của windows-package.yml in
// "CMD_SETUP_SHA256=<sha>" vào nhật ký (nhật ký của lượt đã chạy xong không sửa được), bước đóng gói in "build-info: {…}" (ngày dựng, bản vá an toàn).
// Tệp trong pre-release ci/ / artifact bị thay sau khi chủ thử (kể cả lượt chạy lại bị lỗi đưa đè) → không khớp → từ chối. Trả ngày dựng + cờ bản vá của lượt đó.
export async function kiemNhatKy(src, bd, tep, { ban, nguon = NGUON }) {
  let thay = 0;
  for (const runId of (bd.runIds || []).slice(0, 10)) {
    const jobs = (await src.call('GET', `/repos/${nguon}/actions/runs/${runId}/jobs?per_page=100`))?.jobs || [];
    for (const job of jobs) {
      if (!job || job.conclusion !== 'success' || !Number.isSafeInteger(Number(job.id))) continue;
      const text = await src.docNhatKy(`/repos/${nguon}/actions/jobs/${Number(job.id)}/logs`);
      if (!text) continue;
      const shas = [...new Set([...text.matchAll(/CMD_SETUP_SHA256=([0-9a-f]{64})(?![0-9a-f])/g)].map((m) => m[1]))];
      if (!shas.length) continue;
      thay++;
      if (shas.length !== 1 || shas[0] !== tep.sha256) continue;
      const infos = [...text.matchAll(/build-info: (\{[^\r\n]*\})/g)]
        .map((m) => {
          try {
            return JSON.parse(m[1]);
          } catch {
            return null;
          }
        })
        .filter((x) => x && x.version === ban && /^\d{4}-\d{2}-\d{2}$/.test(String(x.date)));
      const ngay = [...new Set(infos.map((x) => x.date))], va = [...new Set(infos.map((x) => x.safetyPatch === true))];
      if (ngay.length !== 1 || va.length !== 1) throw loi(`Nhật ký lượt dựng CI #${runId} không có đúng một dòng build-info của bản ${ban} — không phát hành.`);
      return { runId, build: ngay[0], safetyPatch: va[0] };
    }
  }
  if (!thay) {
    throw loi(
      `Nhật ký lượt dựng CI của commit ${bd.sha.slice(0, 7)} không có SHA-256 bộ cài (nhật ký đã hết hạn, hoặc bản dựng trước khi CI in CMD_SETUP_SHA256) — đẩy lại commit có [winbuild], thử bản mới rồi bấm lại.`
    );
  }
  throw loi(`Bộ cài lấy được (SHA-256 ${tep.sha256}) KHÔNG phải tệp do lượt dựng CI đã đạt của commit ${bd.sha.slice(0, 7)} dựng ra — có người đã thay tệp; không phát hành. Kiểm Releases ci/ của kho mã nguồn.`);
}

// Tải về tệp (hoặc chỉ băm khi file = null), đếm cỡ, giữ 2 byte đầu; quá MAX_BYTES thì dừng.
export async function taiVe(fetchFn, url, file, { headers = {}, max = MAX_BYTES } = {}) {
  return luuPhanHoi(await fetchFn(url, { headers, redirect: 'follow' }), url, file, { max });
}
async function luuPhanHoi(res, url, file, { max = MAX_BYTES } = {}) {
  if (!res.ok || !res.body) {
    const e = loi(`Tải ${String(url).split('?')[0]} lỗi ${res.status}.`);
    e.status = res.status;
    throw e;
  }
  const h = crypto.createHash('sha256');
  let size = 0, head = Buffer.alloc(0);
  const dem = new Transform({
    transform(chunk, _enc, cb) {
      size += chunk.length;
      if (size > max) return cb(loi(`Tệp vượt ${Math.round(max / 1048576)} MB.`));
      if (head.length < 2) head = Buffer.concat([head, chunk.subarray(0, 2 - head.length)]);
      h.update(chunk);
      cb(null, chunk);
    },
  });
  const dich = file ? fs.createWriteStream(file, { flags: 'wx' }) : new Writable({ write: (_c, _e, cb) => cb() });
  await pipeline(Readable.fromWeb(res.body), dem, dich);
  return { size, sha256: h.digest('hex'), mz: head.toString('latin1') === 'MZ' };
}

// Rà độc lập R12-N1 (2.6.0): lấy MỘT mục của zip ra tệp THƯỜNG do lệnh tự tạo (cờ wx — đường dẫn đã có gì, kể cả liên kết, thì lỗi). unzip -p chỉ in
// nội dung mục: mục là liên kết tượng trưng thì ra chuỗi đích của liên kết, KHÔNG đọc tệp nó trỏ tới. Trước sửa: unzip -o dựng lại liên kết, bước đưa lên
// đọc xuyên liên kết → artifact tự dựng có "sổ tay" trỏ /proc/self/environ đưa khóa ký + mã truy cập lên Releases công khai.
export async function giaiNen(zip, ten, file, { max = MAX_BYTES } = {}) {
  const p = spawn('unzip', ['-p', zip, ten], { stdio: ['ignore', 'pipe', 'ignore'] });
  const xong = new Promise((resolve, reject) => {
    p.on('error', reject);
    p.on('close', (code) => resolve(code));
  });
  let size = 0;
  const dem = new Transform({
    transform(c, _e, cb) {
      size += c.length;
      if (size > max) return cb(loi(`${ten} trong artifact vượt giới hạn.`));
      cb(null, c);
    },
  });
  try {
    await pipeline(p.stdout, dem, fs.createWriteStream(file, { flags: 'wx' }));
  } catch (e) {
    p.kill();
    await xong.catch(() => {});
    throw e;
  }
  const code = await xong;
  if (code !== 0 || !size) throw loi(`Artifact không có ${ten}.`);
  return size;
}
// Tệp tải / giải nén: phải là tệp thường (không liên kết) — kiểm lại ngay trước khi băm / đưa lên.
const tepThuong = (file) => {
  const st = fs.lstatSync(file);
  if (!st.isFile()) throw loi(`${path.basename(file)} không phải tệp thường — không phát hành.`);
  return st;
};
// Sổ tay: tệp thường ≤ 64 MB, mở đầu là trang HTML (<!doctype html / <html, bỏ BOM + khoảng trắng).
function kiemSoTay(file) {
  const st = tepThuong(file);
  if (st.size <= 0 || st.size > SO_TAY_MAX) throw loi('Sổ tay của bản dựng rỗng / quá lớn — không phát hành.');
  const fd = fs.openSync(file, 'r'), head = Buffer.alloc(256);
  let n = 0;
  try {
    n = fs.readSync(fd, head, 0, head.length, 0);
  } finally {
    fs.closeSync(fd);
  }
  const t = head.subarray(0, n).toString('utf8').replace(/^\uFEFF/, '').trimStart().toLowerCase();
  if (!t.startsWith('<!doctype html') && !t.startsWith('<html')) throw loi('Sổ tay của bản dựng không phải trang HTML — không phát hành.');
}

// Tải bộ cài (và sổ tay nếu có) của bản dựng về thư mục tạm; kiểm là tệp chương trình Windows.
export async function taiBoCai(src, bd, { dir, fetchFn, nguon = NGUON, unzip = giaiNen }) {
  const setup = path.join(dir, bd.setupName);
  let soTay = null;
  let info;
  if (bd.nguon === 'release') {
    info = await src.taiQuaApi(`/repos/${nguon}/releases/assets/${bd.assetId}`, setup, { accept: 'application/octet-stream' });
    if (bd.soTayId) {
      soTay = path.join(dir, 'So-tay-CMD-Ke-Toan.html');
      await src.taiQuaApi(`/repos/${nguon}/releases/assets/${bd.soTayId}`, soTay, { accept: 'application/octet-stream', max: 64 * 1048576 });
    }
  } else {
    const zip = path.join(dir, 'ban-dung.zip');
    await src.taiQuaApi(`/repos/${nguon}/actions/artifacts/${bd.artifactId}/zip`, zip);
    try {
      await unzip(zip, bd.setupName, setup, { max: MAX_BYTES });
    } catch {
      throw loi('Artifact của bản dựng không có ' + bd.setupName + ' (hoặc đọc không được).');
    }
    const st0 = path.join(dir, 'So-tay-CMD-Ke-Toan.html');
    try {
      await unzip(zip, 'So-tay-CMD-Ke-Toan.html', st0, { max: SO_TAY_MAX });
      soTay = st0;
    } catch {
      fs.rmSync(st0, { force: true });
      soTay = null;
    }
    fs.rmSync(zip, { force: true });
    tepThuong(setup);
    const h = crypto.createHash('sha256');
    await pipeline(fs.createReadStream(setup), new Writable({ write: (c, _e, cb) => (h.update(c), cb()) }));
    const st = fs.statSync(setup), fd = fs.openSync(setup, 'r'), head = Buffer.alloc(2);
    try {
      fs.readSync(fd, head, 0, 2, 0);
    } finally {
      fs.closeSync(fd);
    }
    info = { size: st.size, sha256: h.digest('hex'), mz: head.toString('latin1') === 'MZ' };
  }
  if (!info.mz) throw loi('Tệp ' + bd.setupName + ' không phải chương trình Windows (.exe).');
  if (info.size <= 0 || info.size > MAX_BYTES) throw loi('Bộ cài vượt giới hạn máy khách nhận.');
  tepThuong(setup);
  if (soTay) kiemSoTay(soTay);
  return { file: setup, name: bd.setupName, size: info.size, sha256: info.sha256, soTay };
}

// Đưa bộ cài lên Releases của kho công khai: tag v<số bản>, đăng dạng BẢN THỬ (prerelease — tải được, không là "Latest"); phatHanh đánh dấu Latest sau khi
// máy chủ key nhận (rà R12 Nhẹ 2: trước sửa đăng Latest ngay, máy chủ từ chối thì trang Releases vẫn trỏ bản đó). Chạy lại: bản nháp cũ của số bản này bị
// xóa; release đã có thì phải đúng bộ cài.
export async function dangRelease(pub, repo, vao, tep, { fetchFn, sleep }) {
  const tag = 'v' + vao.ban;
  const url = `https://github.com/${repo}/releases/download/${tag}/${tep.name}`;
  for (const r of await pub.pages(`/repos/${repo}/releases`)) {
    if (r?.draft && (r.tag_name === tag || r.name === `CMD Kế toán ${vao.ban}`)) await pub.call('DELETE', `/repos/${repo}/releases/${r.id}`);
  }
  const co = await pub.call('GET', `/repos/${repo}/releases/tags/${tag}`, { okNull: true });
  if (co) {
    // Rà R12 Nhẹ 4: tách "thiếu / khác bộ cài" (xóa release rồi bấm lại) khỏi lỗi tải tạm thời (KHÔNG xóa — có thể là bản máy chủ đang phát).
    if (!(co.assets || []).some((x) => x && x.name === tep.name)) {
      throw loi(`Kho công khai đã có release ${tag} nhưng thiếu ${tep.name} — xóa release ${tag} (Releases → ${tag} → Delete) rồi bấm lại.`);
    }
    try {
      await kiemTaiCongKhai(fetchFn, url, tep, { ...(sleep ? { sleep } : {}), lan: 3 });
    } catch (e) {
      if (e.code === 'SHA_KHAC') throw loi(`Kho công khai đã có release ${tag} nhưng bộ cài khác bộ cài của bản dựng — xóa release ${tag} (Releases → ${tag} → Delete) rồi bấm lại.`);
      throw loi(`Kho công khai đã có release ${tag} nhưng chưa tải được bộ cài từ địa chỉ công khai (${gon(e.message)}) — KHÔNG xóa release; bấm lại sau ít phút.`);
    }
    return { url, moi: false, id: co.id, prerelease: co.prerelease === true };
  }
  const body = [
    `CMD Kế toán ${vao.ban} — bộ cài cho Windows 64-bit.`,
    vao.ghiChu,
    `Bộ cài: ${tep.name} — SHA-256 ${tep.sha256}`,
    tep.soTay ? 'Sổ tay mở không cần mạng: So-tay-CMD-Ke-Toan.html' : '',
    `Máy đang dùng CMD từ ${vao.tuBan} trở lên: mở CMD → khung "Có bản CMD mới" → Cập nhật.`,
  ]
    .filter(Boolean)
    .join('\n\n');
  const rel = await pub.call('POST', `/repos/${repo}/releases`, { body: { tag_name: tag, name: `CMD Kế toán ${vao.ban}`, body, draft: true, prerelease: false } });
  const upload = String(rel.upload_url || '').replace(/\{.*\}$/, '');
  if (!/^https:\/\/uploads\.github\.com\//.test(upload)) throw loi('GitHub không trả địa chỉ đưa tệp lên.');
  const gui = async (file, name, type) => {
    tepThuong(file);
    const res = await fetchFn(`${upload}?name=${encodeURIComponent(name)}`, {
      method: 'POST',
      headers: { authorization: 'Bearer ' + pub.token, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28', 'user-agent': 'cmd-phat-hanh', 'content-type': type },
      body: fs.readFileSync(file),
    });
    if (!res.ok) throw loi(`Đưa ${name} lên GitHub lỗi ${res.status}.`);
  };
  await gui(tep.file, tep.name, 'application/octet-stream');
  if (tep.soTay) await gui(tep.soTay, 'So-tay-CMD-Ke-Toan.html', 'text/html');
  await pub.call('PATCH', `/repos/${repo}/releases/${rel.id}`, { body: { draft: false, prerelease: true, make_latest: 'false' } });
  return { url, moi: true, id: rel.id, prerelease: true };
}

// Tải lại từ địa chỉ công khai (như máy khách) — phải đúng từng byte đã băm; thử lại khi GitHub chưa kịp phân phối.
export async function kiemTaiCongKhai(fetchFn, url, tep, { sleep = (ms) => new Promise((r) => setTimeout(r, ms)), lan = 6 } = {}) {
  let last = null;
  for (let i = 0; i < lan; i++) {
    let r = null;
    try {
      r = await taiVe(fetchFn, url, null);
    } catch (e) {
      last = e;// chưa phân phối xong / lỗi mạng → thử lại
    }
    if (r) {
      if (r.sha256 === tep.sha256 && r.size === tep.size) return r;
      throw Object.assign(loi(`Tệp tải từ ${url} khác bộ cài vừa đưa lên (SHA-256 ${r.sha256}) — chưa báo máy chủ.`), { code: 'SHA_KHAC' });
    }
    if (i < lan - 1) await sleep(10000);
  }
  throw loi(`Chưa tải được bộ cài từ địa chỉ công khai (${gon(last?.message)}) — chưa báo máy chủ; bấm lại sau ít phút.`);
}

export async function banDangPhatHanh(fetchFn, mayChu) {
  const res = await fetchFn(mayChu + '/v1/update?channel=stable', { headers: { 'user-agent': 'cmd-phat-hanh' } });
  const j = await res.json().catch(() => null);
  if (!res.ok || !j || j.ok !== true) throw loi(`Máy chủ key chưa trả lời (${res.status}) — kiểm máy chủ (quy trình "Cập nhật máy chủ key") rồi bấm lại.`);
  return j.update ? { compact: j.update, ...payloadOf(j.update) } : null;
}

export async function baoMayChu(fetchFn, mayChu, token, compact) {
  const res = await fetchFn(mayChu + '/ci/v1/update', {
    method: 'POST',
    headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json', 'user-agent': 'cmd-phat-hanh' },
    body: JSON.stringify({ manifest: compact }),
  });
  const j = await res.json().catch(() => null);
  if (!res.ok || !j || j.ok !== true) throw loi(`Máy chủ key từ chối (${res.status}): ${gon(j?.error?.message || '')}`);
  return { version: String(j.version || ''), previous: j.previous && VERSION_RE.test(String(j.previous)) ? String(j.previous) : null, already: j.already === true, withdrawn: Array.isArray(j.withdrawn) ? j.withdrawn.map(String) : [] };
}

// Xóa release v<x.y.z> cũ hơn bản vừa phát hành, trừ bản giữ lại (bản liền trước mà máy chủ còn phát hành). Không đụng release khác dạng / mới hơn.
export async function donBanCu(pub, repo, { ban, giu }) {
  const xoa = [];
  for (const r of await pub.pages(`/repos/${repo}/releases`)) {
    const m = /^v(\d{1,4}\.\d{1,4}\.\d{1,6}(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?)$/.exec(String(r?.tag_name || ''));
    if (!m || r.draft || giu.includes(m[1]) || compareVersions(m[1], ban) >= 0) continue;
    await pub.call('DELETE', `/repos/${repo}/releases/${r.id}`);
    await pub.call('DELETE', `/repos/${repo}/git/refs/tags/${encodeURIComponent(r.tag_name)}`, { okNull: true });
    xoa.push(m[1]);
  }
  return xoa;
}

export async function phatHanh(env = process.env, deps = {}) {
  const { fetchFn = globalThis.fetch, log = console.log, now = () => new Date(), unzip = giaiNen, sleep, mayChu = MAY_CHU, nguon = NGUON, khoaCongKhai = KHOA_CONG_KHAI_U1 } = deps;
  const vao = kiemDauVao(env);
  for (const k of ['NGUON_TOKEN', 'CMD_UPDATE_KEY', 'CMD_PHAT_HANH_TOKEN', 'GH_TOKEN', 'GITHUB_REPOSITORY']) {
    if (!String(env[k] || '').trim()) throw loi(`Thiếu ${k} — kho cmd-ketoan-ban-cai → Settings → Secrets and variables → Actions (hướng dẫn: README máy chủ key, mục "Hai nút trên GitHub").`);
  }
  const repo = String(env.GITHUB_REPOSITORY);
  if (!/^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/.test(repo)) throw loi('GITHUB_REPOSITORY không hợp lệ.');
  const key = khoaRieng(env.CMD_UPDATE_KEY, khoaCongKhai);
  const src = taoGithub(String(env.NGUON_TOKEN).trim(), fetchFn), pub = taoGithub(String(env.GH_TOKEN).trim(), fetchFn);

  log(`[1/8] Bản đang phát hành trên máy chủ key`);
  const dang = await banDangPhatHanh(fetchFn, mayChu);
  log('  ' + (dang ? dang.version : 'chưa có bản nào'));
  if (dang && compareVersions(dang.version, vao.ban) > 0) throw loi(`Máy chủ đang phát hành ${dang.version}, mới hơn ${vao.ban} — không phát hành bản cũ hơn.`);

  log(`[2/8] Tìm bộ cài của bản dựng ${vao.ban}`);
  const bd = await timBanDung(src, { ban: vao.ban, commit: vao.commit, nguon });
  log(`  commit ${bd.sha.slice(0, 7)} — lượt dựng CI đã đạt; lấy từ ${bd.nguon === 'release' ? 'Releases ci/' + vao.ban + '-' + bd.tag : 'artifact'}`);

  log('[3/8] Tải bộ cài, đối chiếu SHA-256 với nhật ký lượt dựng CI');
  const dir = fs.mkdtempSync(path.join(env.RUNNER_TEMP || os.tmpdir(), 'cmd-ph-'));
  try {
    const tep = await taiBoCai(src, bd, { dir, fetchFn, nguon, unzip });
    log(`  ${tep.name} — ${mb(tep.size)} MB, SHA-256 ${tep.sha256}`);
    const nk = await kiemNhatKy(src, bd, tep, { ban: vao.ban, nguon });
    log(`  khớp nhật ký lượt dựng CI #${nk.runId} — ngày dựng ${nk.build}`);
    if (dang && dang.version === vao.ban && dang.sha256 !== tep.sha256) {
      throw loi(`Máy chủ đang phát hành ${vao.ban} với bộ cài khác — không thay bộ cài của số bản đã phát hành; tăng số bản, dựng lại, thử rồi bấm lại.`);
    }

    log(`[4/8] Đưa lên Releases của ${repo} (tag v${vao.ban}, dạng bản thử tới khi máy chủ key nhận)`);
    const rel = await dangRelease(pub, repo, vao, tep, { fetchFn, sleep });
    log('  ' + (rel.moi ? 'đã tạo release v' + vao.ban : 'release v' + vao.ban + ' đã có, đúng bộ cài — dùng lại'));
    // Máy chủ từ chối / chưa trả đúng bản → xóa release VỪA TẠO ở lượt này (không đụng release đã có từ trước — có thể là bản máy chủ đang phát).
    const goRelease = async () => {
      if (!rel.moi) return;
      const sv = await banDangPhatHanh(fetchFn, mayChu).catch(() => null);
      if (sv && sv.url === rel.url) return;
      await pub.call('DELETE', `/repos/${repo}/releases/${rel.id}`);
      await pub.call('DELETE', `/repos/${repo}/git/refs/tags/${encodeURIComponent('v' + vao.ban)}`, { okNull: true });
      log(`  đã xóa release v${vao.ban} vừa tạo`);
    };

    log('[5/8] Tải lại từ địa chỉ công khai, kiểm SHA-256');
    try {
      await kiemTaiCongKhai(fetchFn, rel.url, tep, sleep ? { sleep } : {});
    } catch (e) {
      await goRelease().catch(() => {});
      throw e;
    }

    log('[6/8] Ký bản kê cập nhật');
    const t = now();
    const compact = kyBanKe(
      { version: vao.ban, build: nk.build, safetyPatch: nk.safetyPatch, url: rel.url, size: tep.size, sha256: tep.sha256, notes: vao.ghiChu, minFrom: vao.tuBan, publishedAt: t.toISOString() },
      key,
      khoaCongKhai
    );

    log('[7/8] Báo máy chủ key');
    let kq;
    try {
      kq = await baoMayChu(fetchFn, mayChu, String(env.CMD_PHAT_HANH_TOKEN).trim(), compact);
      const sau = await banDangPhatHanh(fetchFn, mayChu);
      if (!sau || sau.version !== vao.ban || sau.sha256 !== tep.sha256 || sau.url !== rel.url) {
        throw loi('Máy chủ chưa trả bản vừa đăng ở /v1/update — mở trang quản trị → Cập nhật kiểm lại; chưa xóa bản cũ nào.');
      }
    } catch (e) {
      await goRelease().catch(() => {});
      throw e;
    }
    log('  ' + (kq.already ? 'máy chủ đã có đúng bản này (lần chạy trước)' : 'đã đăng') + (kq.withdrawn.length ? '; máy chủ tự gỡ ' + kq.withdrawn.join(', ') : ''));
    if (rel.prerelease) await pub.call('PATCH', `/repos/${repo}/releases/${rel.id}`, { body: { prerelease: false, make_latest: 'true' } });

    const giu = [vao.ban, kq.previous].filter(Boolean);
    log(`[8/8] Xóa bản cũ trên Releases (giữ ${giu.join(' và ')})`);
    const xoa = await donBanCu(pub, repo, { ban: vao.ban, giu });
    log('  ' + (xoa.length ? 'đã xóa ' + xoa.join(', ') : 'không có bản cũ cần xóa'));

    const tom = [
      `## Đã phát hành CMD ${vao.ban}`,
      '',
      `- Bộ cài: ${rel.url}`,
      `- Cỡ ${mb(tep.size)} MB, SHA-256 \`${tep.sha256}\` (commit ${bd.sha.slice(0, 7)})`,
      `- Ngày dựng ${nk.build} (lượt dựng CI #${nk.runId}); máy đang chạy CMD từ ${vao.tuBan} trở lên thấy khung "Có bản CMD mới"${nk.safetyPatch ? ' — bản vá an toàn (key hết hạn cập nhật vẫn nhận)' : ''}`,
      `- Giữ lại: ${giu.join(', ')}${xoa.length ? '; đã xóa: ' + xoa.join(', ') : ''}`,
      '- Bản mới lỗi: trang quản trị → Cập nhật → Gỡ — khách quay về bản liền trước.',
    ].join('\n');
    if (env.GITHUB_STEP_SUMMARY) fs.appendFileSync(env.GITHUB_STEP_SUMMARY, tom + '\n');
    return { ban: vao.ban, sha: bd.sha, url: rel.url, sha256: tep.sha256, size: tep.size, compact, previous: kq.previous, xoa };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

export async function tim(env = process.env, deps = {}) {
  const { fetchFn = globalThis.fetch, log = console.log, nguon = NGUON } = deps;
  const ban = kiemBan(env.BAN), commit = kiemCommit(env.COMMIT);
  if (!String(env.NGUON_TOKEN || '').trim()) throw loi('Thiếu NGUON_TOKEN — kho cmd-ketoan-ban-cai → Settings → Secrets and variables → Actions.');
  const bd = await timBanDung(taoGithub(String(env.NGUON_TOKEN).trim(), fetchFn), { ban, commit, nguon });
  if (env.GITHUB_OUTPUT) fs.appendFileSync(env.GITHUB_OUTPUT, `sha=${bd.sha}\n`);
  log(`Bản dựng ${ban}: commit ${bd.sha.slice(0, 7)} (lượt dựng CI đã đạt).`);
  return bd;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const lenh = { 'phat-hanh': phatHanh, tim }[process.argv[2]];
  if (!lenh) {
    console.error('Dùng: node phat-hanh.mjs phat-hanh | tim');
    process.exitCode = 2;
  } else {
    lenh(process.env).then(
      () => {},
      (e) => {
        console.log('::error::' + String(e?.message || e).replace(/\r?\n/g, ' '));
        process.exitCode = 1;
      }
    );
  }
}

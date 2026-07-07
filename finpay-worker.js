/**
 * FinPay backend — Cloudflare Worker
 * -----------------------------------------------------------------
 * Routes:
 *   POST /otp/start          { phone, purpose }              -> kirim OTP via LoginWA
 *   POST /otp/verify         { phone, session_id, otp_code, name? } -> verifikasi + buat akun + session_token
 *   GET  /balance/:accountId                                  -> saldo akun
 *   POST /trx/pulsa          (Bearer session_token) { product, dest, quantity?, ref_id? } -> beli via H2H.id
 *   GET  /products/pulsa     ?phone=08xx (Bearer)             -> daftar nominal & harga ASLI dari h2h_products (auto deteksi operator dari nomor)
 *   GET  /wallet/my-code     (Bearer session_token)            -> ambil/generate kode wallet sendiri
 *   GET  /wallet/lookup      ?code=... atau ?phone=... (Bearer) -> intip nama penerima sebelum kirim
 *   POST /wallet/transfer    { to_code|to_phone, amount, note? } (Bearer + Idempotency-Key) -> kirim saldo
 *   GET  /topup/methods      (Bearer)                          -> daftar channel pembayaran aktif (Sakurupiah + QRIS.pw)
 *   POST /topup/create       (Bearer) { method, amount }        -> bikin invoice (QRIS/E-wallet/VA via Sakurupiah, atau QRISPW via QRIS.pw)
 *   GET  /topup/status/:merchant_ref (Bearer)                  -> cek status top up (lokal + fallback ke gateway terkait)
 *   POST /topup/callback                                       -> webhook dari Sakurupiah, credit saldo otomatis
 *   POST /topup/qris-callback                                  -> webhook dari QRIS.pw (worker terpisah), credit saldo otomatis
 *
 * Required secrets (set with `wrangler secret put <NAME>`):
 *   SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, LOGINWA_API_KEY, SESSION_SECRET
 *   SAKURUPIAH_API_ID, SAKURUPIAH_API_KEY
 *   QRISPW_WORKER_URL       -> URL worker QRIS.pw yang SUDAH ADA (punya endpoint terpisah, worker lain, punya app lain juga)
 *   QRISPW_SHARED_SECRET    -> string rahasia, HARUS SAMA PERSIS dengan FINPAY_SHARED_SECRET yang di-set di worker QRIS.pw
 *   QRISPW_WEBHOOK_SECRET   -> webhook_secret dari dashboard qris.pw, dipakai untuk verifikasi tanda tangan webhook
 *
 * H2H.id credentials disimpan di Supabase (h2h_config, h2h_products), bukan sebagai
 * secret di Worker, supaya bisa diupdate langsung dari Supabase tanpa redeploy.
 * -----------------------------------------------------------------
 */

// ---------------------------------------------------------------------
// KONFIGURASI — sudah diisi langsung, tinggal copy-paste worker ini.
// ---------------------------------------------------------------------
const CONFIG = {
  SUPABASE_URL: 'https://qlozoubmribwcnyvlcad.supabase.co',
  SUPABASE_SERVICE_ROLE_KEY:
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFsb3pvdWJtcmlid2NueXZsY2FkIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3OTYwNDgxOSwiZXhwIjoyMDk1MTgwODE5fQ.DL6Hq4q9Q-pWd8U5LhZLfA1-mDc8uU0oMuWwrciCI2A',
  LOGINWA_API_KEY: 'sec_HcRXHyuym5OEM1M8mGTE9mZzmUbWQBcSLEzD33xbL2RkCO2F',
  SESSION_SECRET: 'Ervin@123',

  // --- Sakurupiah Payment Gateway (Top Up) ---
  SAKURUPIAH_API_ID: 'ID-78910851439',
  SAKURUPIAH_API_KEY: 'KEY-yMwiJWeuoIMfDgTAohc7pUjW706Nu',
  SAKURUPIAH_BASE_URL: 'https://sakurupiah.id/api',
  WORKER_BASE_URL: 'https://finpay-backend.vinzprostore.workers.dev',
  APP_BASE_URL: 'https://finpay.vinzprostore.workers.dev',

  TOPUP_ALLOWED_METHODS: [
    'QRIS', 'QRISC',
    'DANA', 'GOPAY', 'OVO', 'ShopeePay', 'LinkAja',
    'BCAVA', 'BNIVA', 'BRIVA', 'MANDIRIVA', 'PERMATAVA', 'CIMBVA',
  ],

  // --- QRIS.pw (worker TERPISAH, jangan digabung filenya — cuma dipanggil via HTTP) ---
  QRISPW_WORKER_URL: 'https://qris-gateway.vinzprostore.workers.dev',
  // String rahasia yang sudah di-generate. WAJIB set nilai yang SAMA PERSIS sebagai
  // secret `FINPAY_SHARED_SECRET` di worker qris-gateway.vinzprostore.workers.dev:
  //   wrangler secret put FINPAY_SHARED_SECRET
  //   (lalu paste nilai di bawah ini saat diminta)
  QRISPW_SHARED_SECRET: '6c20f8d7850fce300116d5a7fbb9bdeda8060bee7322ef73807bb4fced9f92de',
  // BELUM ADA field 'webhook_secret' terpisah di dashboard qris.pw (sudah dicek: tab
  // Keamanan/Notifikasi/Webhook/API Keys tidak ada). Dipakai API Secret dari halaman
  // "API Keys" sebagai signing secret — INI ASUMSI, WAJIB DIVALIDASI dengan transaksi
  // test asli (lihat log di Cloudflare kalau signature 'Invalid signature' terus muncul,
  // berarti asumsi ini salah dan perlu tanya support qris.pw langsung via WhatsApp).
  QRISPW_WEBHOOK_SECRET: 'bdd265660fe0e77c93dbf1f95722ccd3857ed59cd8a70be0c26ed01bbec1e263',
};

const SUPABASE_HEADERS = (env) => ({
  apikey: env.SUPABASE_SERVICE_ROLE_KEY,
  Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
  'Content-Type': 'application/json',
});

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
  });
}

function normalizePhone(phone) {
  let p = String(phone || '').replace(/\D/g, '');
  if (p.startsWith('0')) p = '62' + p.slice(1);
  if (!p.startsWith('62')) p = '62' + p;
  return p;
}

// ---------------------------------------------------------------------
// Session tokens (HMAC-signed, no external deps)
// ---------------------------------------------------------------------
const enc = new TextEncoder();

function b64url(bytes) {
  let str = btoa(String.fromCharCode(...new Uint8Array(bytes)));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlToBytes(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
async function hmacKey(env) {
  return crypto.subtle.importKey('raw', enc.encode(env.SESSION_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
async function signSession(env, accountId, ttlSeconds = 60 * 60 * 24 * 30) {
  const payload = JSON.stringify({ sub: accountId, exp: Math.floor(Date.now() / 1000) + ttlSeconds });
  const payloadB64 = b64url(enc.encode(payload));
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(env), enc.encode(payloadB64));
  return `${payloadB64}.${b64url(sig)}`;
}
async function verifySession(env, token) {
  if (!token) return null;
  const [payloadB64, sigB64] = String(token).split('.');
  if (!payloadB64 || !sigB64) return null;
  const valid = await crypto.subtle.verify('HMAC', await hmacKey(env), b64urlToBytes(sigB64), enc.encode(payloadB64));
  if (!valid) return null;
  const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(payloadB64)));
  if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload.sub;
}
async function requireAccount(request, env) {
  const m = (request.headers.get('Authorization') || '').match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  return verifySession(env, m[1]);
}

// ---------------------------------------------------------------------
// PIN hashing (PBKDF2-SHA256)
// ---------------------------------------------------------------------
async function hashPin(pin, iterations = 100000) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, keyMaterial, 256);
  const hashHex = Array.from(new Uint8Array(bits)).map((b) => b.toString(16).padStart(2, '0')).join('');
  const saltHex = Array.from(salt).map((b) => b.toString(16).padStart(2, '0')).join('');
  return `${iterations}:${saltHex}:${hashHex}`;
}
async function verifyPin(pin, stored) {
  const [iterationsStr, saltHex, hashHex] = String(stored || '').split(':');
  if (!iterationsStr || !saltHex || !hashHex) return false;
  const salt = new Uint8Array(saltHex.match(/.{2}/g).map((b) => parseInt(b, 16)));
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: parseInt(iterationsStr, 10), hash: 'SHA-256' }, keyMaterial, 256);
  const computedHex = Array.from(new Uint8Array(bits)).map((b) => b.toString(16).padStart(2, '0')).join('');
  return computedHex === hashHex;
}

// ---------------------------------------------------------------------
// Supabase REST helpers
// ---------------------------------------------------------------------
async function sbSelect(env, table, query) {
  const res = await fetch(`${env.SUPABASE_URL}/rest/v1/${table}?${query}`, { headers: SUPABASE_HEADERS(env) });
  if (!res.ok) throw new Error(`Supabase select ${table} failed: ${await res.text()}`);
  return res.json();
}
async function sbInsert(env, table, row) {
  const res = await fetch(`${env.SUPABASE_URL}/rest/v1/${table}`, {
    method: 'POST',
    headers: { ...SUPABASE_HEADERS(env), Prefer: 'return=representation' },
    body: JSON.stringify(row),
  });
  if (!res.ok) throw new Error(`Supabase insert ${table} failed: ${await res.text()}`);
  return (await res.json())[0];
}
async function sbUpdate(env, table, query, patch) {
  const res = await fetch(`${env.SUPABASE_URL}/rest/v1/${table}?${query}`, {
    method: 'PATCH',
    headers: { ...SUPABASE_HEADERS(env), Prefer: 'return=representation' },
    body: JSON.stringify(patch),
  });
  if (!res.ok) throw new Error(`Supabase update ${table} failed: ${await res.text()}`);
  return res.json();
}
async function sbRpc(env, fn, args) {
  const res = await fetch(`${env.SUPABASE_URL}/rest/v1/rpc/${fn}`, {
    method: 'POST',
    headers: SUPABASE_HEADERS(env),
    body: JSON.stringify(args),
  });
  if (!res.ok) throw new Error(`Supabase rpc ${fn} failed: ${await res.text()}`);
  return res.json();
}

// ---------------------------------------------------------------------
// LoginWA (WhatsApp OTP)
// ---------------------------------------------------------------------
async function loginwaStart(env, phone) {
  const res = await fetch('https://api.loginwa.com/api/v1/auth/start', {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.LOGINWA_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ phone: `+${phone}` }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.message || 'Gagal mengirim OTP');
  return data;
}
async function loginwaVerify(env, sessionId, otpCode) {
  const res = await fetch('https://api.loginwa.com/api/v1/auth/verify', {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.LOGINWA_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId, otp_code: otpCode }),
  });
  const data = await res.json();
  return { ok: res.ok, data };
}

// ---------------------------------------------------------------------
// H2H.id (PPOB reguler + SMM)
// ---------------------------------------------------------------------
const H2H_BASE_URL = 'https://api.h2h.id/api';

async function getH2HConfig(env) {
  const [row] = await sbSelect(env, 'h2h_config', 'id=eq.1&select=*');
  if (!row) throw new Error('h2h_config kosong. Isi dulu tabel h2h_config di Supabase.');
  return row;
}
async function getOfficialProduct(env, productCode) {
  const [row] = await sbSelect(
    env, 'h2h_products',
    `product_code=eq.${encodeURIComponent(productCode)}&is_active=eq.true&select=*&limit=1`
  );
  return row || null;
}
async function h2hOldGet(path, params, creds) {
  const qs = new URLSearchParams({ ...params, memberID: creds.member_id, pin: creds.pin, password: creds.password });
  const res = await fetch(`${H2H_BASE_URL}${path}?${qs.toString()}`);
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok && (data.status === true || data.success === true), data };
}
async function h2hOrder(env, creds, { product, isSmm, dest, quantity, refID }) {
  if (isSmm) {
    return h2hOldGet('/trx', { type: 'smm', service: product, target: dest, quantity: quantity || 1, refID }, creds);
  }
  return h2hOldGet('/trx', { product, dest, refID }, creds);
}
async function upsertH2HTransaction(env, row) {
  const res = await fetch(`${env.SUPABASE_URL}/rest/v1/h2h_transactions?on_conflict=ref_id`, {
    method: 'POST',
    headers: { ...SUPABASE_HEADERS(env), Prefer: 'resolution=merge-duplicates,return=representation' },
    body: JSON.stringify(row),
  });
  if (!res.ok) throw new Error(`Gagal simpan h2h_transactions: ${await res.text()}`);
  return (await res.json())[0];
}

// ---------------------------------------------------------------------
// Akun admin/owner: transaksi TIDAK motong saldo FinPay (account_balances),
// TIDAK kena biaya admin, dan saldo yang ditampilkan di /balance adalah saldo
// deposit H2H.id langsung (bukan saldo wallet FinPay).
// Tambahkan nomor lain ke daftar ini kalau mau lebih dari satu admin.
// Format nomor SUDAH dinormalisasi (62xxx), sama seperti keluaran normalizePhone().
// ---------------------------------------------------------------------
const ADMIN_PHONES = ['6282147534549'];

async function isAdminAccount(env, accountId) {
  if (!accountId) return false;
  const [account] = await sbSelect(env, 'accounts', `id=eq.${accountId}&select=phone_number`);
  return !!account && ADMIN_PHONES.includes(account.phone_number);
}

async function h2hCheckBalance(env) {
  const creds = await getH2HConfig(env);
  return h2hOldGet('/trx/balance', {}, creds);
}

// ---------------------------------------------------------------------
// Deteksi operator dari 4 digit awal nomor HP (untuk endpoint /products/pulsa)
// ---------------------------------------------------------------------
const PREFIX_TO_OPERATOR = {
  // Telkomsel
  '0811': 'Telkomsel', '0812': 'Telkomsel', '0813': 'Telkomsel', '0821': 'Telkomsel',
  '0822': 'Telkomsel', '0823': 'Telkomsel', '0852': 'Telkomsel', '0853': 'Telkomsel',
  // Indosat
  '0814': 'Indosat', '0815': 'Indosat', '0816': 'Indosat', '0855': 'Indosat',
  '0856': 'Indosat', '0857': 'Indosat', '0858': 'Indosat',
  // XL
  '0817': 'XL', '0818': 'XL', '0819': 'XL', '0859': 'XL', '0877': 'XL', '0878': 'XL',
  // Axis
  '0838': 'Axis', '0831': 'Axis', '0832': 'Axis', '0833': 'Axis',
  // Tri
  '0895': 'Tri', '0896': 'Tri', '0897': 'Tri', '0898': 'Tri', '0899': 'Tri',
  // Smartfren
  '0881': 'Smartfren', '0882': 'Smartfren', '0883': 'Smartfren', '0884': 'Smartfren',
  '0885': 'Smartfren', '0886': 'Smartfren', '0887': 'Smartfren', '0888': 'Smartfren', '0889': 'Smartfren',
};
function detectOperator(phone) {
  let p = String(phone || '').replace(/\D/g, '');
  if (p.startsWith('62')) p = '0' + p.slice(2);
  if (!p.startsWith('0')) p = '0' + p;
  const prefix = p.slice(0, 4);
  return PREFIX_TO_OPERATOR[prefix] || null;
}

// ---------------------------------------------------------------------
// Sakurupiah Payment Gateway (Top Up saldo)
// ---------------------------------------------------------------------
async function hmacSha256Hex(message, secret) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, '0')).join('');
}
async function sakurupiahSignatureCreate(env, method, merchantRef, amount) {
  const raw = `${env.SAKURUPIAH_API_ID}${method}${merchantRef}${amount}`;
  return hmacSha256Hex(raw, env.SAKURUPIAH_API_KEY);
}
async function sakurupiahListPayment(env) {
  const res = await fetch(`${env.SAKURUPIAH_BASE_URL}/list-payment.php`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Bearer ${env.SAKURUPIAH_API_KEY}` },
    body: new URLSearchParams({ api_id: env.SAKURUPIAH_API_ID, method: 'list' }).toString(),
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok && data.status === '200', data };
}
async function sakurupiahCreateInvoice(env, { method, name, email, phone, amount, merchantFee, merchantRef, expired }) {
  const signature = await sakurupiahSignatureCreate(env, method, merchantRef, amount);
  const body = new URLSearchParams({
    api_id: env.SAKURUPIAH_API_ID,
    method,
    name: name || 'Pengguna FinPay',
    phone,
    amount: String(amount),
    merchant_fee: String(merchantFee != null ? merchantFee : 1),
    merchant_ref: merchantRef,
    expired: String(expired || 1),
    callback_url: `${env.WORKER_BASE_URL}/topup/callback`,
    return_url: `${env.APP_BASE_URL}/`,
    signature,
  });
  if (email) body.set('email', email);
  const res = await fetch(`${env.SAKURUPIAH_BASE_URL}/create.php`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Bearer ${env.SAKURUPIAH_API_KEY}` },
    body: body.toString(),
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok && data.status === '200', data };
}
async function sakurupiahCheckStatus(env, trxId) {
  const res = await fetch(`${env.SAKURUPIAH_BASE_URL}/status-transaction.php`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Bearer ${env.SAKURUPIAH_API_KEY}` },
    body: new URLSearchParams({ api_id: env.SAKURUPIAH_API_ID, method: 'status', trx_id: trxId }).toString(),
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok && data.status === '200', data };
}

// ---------------------------------------------------------------------
// QRIS.pw (worker TERPISAH — cuma dipanggil lewat HTTP, filenya tidak digabung)
// Worker QRIS.pw harus punya endpoint tambahan:
//   POST /finpay/create-payment   (lihat file qrispw-worker-tambahan.js)
//   GET  /finpay/check-payment
// ---------------------------------------------------------------------
async function qrispwCreateInvoice(env, { amount, merchantRef, name, phone }) {
  const res = await fetch(`${env.QRISPW_WORKER_URL}/finpay/create-payment`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Finpay-Secret': env.QRISPW_SHARED_SECRET },
    body: JSON.stringify({
      amount,
      order_id: merchantRef,
      customer_name: name || 'Pengguna FinPay',
      customer_phone: phone,
      callback_url: `${env.WORKER_BASE_URL}/topup/qris-callback`,
    }),
  });
  const rawText = await res.text();
  let data;
  try {
    data = JSON.parse(rawText);
  } catch (err) {
    // Respons dari qris-gateway BUKAN JSON valid (kemungkinan 404/HTML/error Cloudflare).
    // Simpan status + potongan body asli supaya kelihatan di provider_message, bukan pesan generik.
    data = { error: `qris-gateway balas non-JSON (HTTP ${res.status}): ${rawText.slice(0, 200)}` };
  }
  return { ok: res.ok && data.success === true, data };
}
async function qrispwCheckStatus(env, transactionId) {
  const res = await fetch(`${env.QRISPW_WORKER_URL}/finpay/check-payment?transaction_id=${encodeURIComponent(transactionId)}`, {
    headers: { 'X-Finpay-Secret': env.QRISPW_SHARED_SECRET },
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, data };
}

// ---------------------------------------------------------------------
// Route handlers — Auth
// ---------------------------------------------------------------------
async function handleOtpStart(req, env) {
  const { phone, purpose } = await req.json();
  if (!phone || !purpose) return json({ status: false, message: 'phone dan purpose wajib diisi' }, 400);
  const normalized = normalizePhone(phone);
  const wa = await loginwaStart(env, normalized);
  await sbInsert(env, 'otp_sessions', { phone_number: normalized, purpose, loginwa_session_id: wa.session_id, status: 'pending' });
  return json({ status: true, message: 'OTP dikirim via WhatsApp', session_id: wa.session_id });
}

async function handleOtpVerify(req, env) {
  const { phone, session_id, otp_code, name, pin } = await req.json();
  if (!phone || !session_id || !otp_code) {
    return json({ status: false, message: 'phone, session_id, otp_code wajib diisi' }, 400);
  }
  const normalized = normalizePhone(phone);
  const [existingSession] = await sbSelect(env, 'otp_sessions', `loginwa_session_id=eq.${session_id}&select=*`);
  const alreadyVerified = existingSession && existingSession.status === 'verified';

  if (!alreadyVerified) {
    const verify = await loginwaVerify(env, session_id, otp_code);
    if (!verify.ok) {
      await sbUpdate(env, 'otp_sessions', `loginwa_session_id=eq.${session_id}`, { status: 'failed', attempts: (verify.data.attempts || 0) + 1 });
      return json({ status: false, message: verify.data.message || 'Kode OTP salah atau kedaluwarsa' }, 400);
    }
    await sbUpdate(env, 'otp_sessions', `loginwa_session_id=eq.${session_id}`, { status: 'verified', verified_at: new Date().toISOString() });
  }

  let [account] = await sbSelect(env, 'accounts', `phone_number=eq.${normalized}&select=*`);
  if (!account) {
    if (!name) return json({ status: false, code: 'not_registered', message: 'Nomor belum terdaftar di FinPay.' }, 404);
    if (!pin || !/^\d{6}$/.test(pin)) return json({ status: false, message: 'PIN 6 digit wajib diisi untuk akun baru.' }, 400);
    account = await sbInsert(env, 'accounts', { phone_number: normalized, name: name, pin_hash: await hashPin(pin), is_phone_verified: true });
  } else if (!account.is_phone_verified) {
    [account] = await sbUpdate(env, 'accounts', `id=eq.${account.id}`, { is_phone_verified: true });
  }

  await sbUpdate(env, 'otp_sessions', `loginwa_session_id=eq.${session_id}`, { status: 'verified', account_id: account.id, verified_at: new Date().toISOString() });
  const session_token = await signSession(env, account.id);
  const { pin_hash, ...safeAccount } = account;
  return json({ status: true, message: 'Verifikasi berhasil', account: safeAccount, has_pin: !!pin_hash, session_token });
}

async function handleGetBalance(accountId, env) {
  if (await isAdminAccount(env, accountId)) {
    const h2hBal = await h2hCheckBalance(env);
    if (!h2hBal.ok) return json({ status: false, message: (h2hBal.data && h2hBal.data.message) || 'Gagal ambil saldo H2H.id' }, 502);
    const raw = h2hBal.data.data || h2hBal.data;
    const balance = Number(raw && raw.balance) || 0;
    return json({ status: true, data: { balance, updated_at: new Date().toISOString(), source: 'h2h' } });
  }
  const [row] = await sbSelect(env, 'account_balances', `account_id=eq.${accountId}&select=balance,updated_at`);
  if (!row) return json({ status: false, message: 'Akun tidak ditemukan' }, 404);
  return json({ status: true, data: row });
}

// ---------------------------------------------------------------------
// NEW: GET /products/pulsa?phone=08xx
// Daftar nominal pulsa + harga ASLI (langsung dari tabel h2h_products),
// dideteksi otomatis dari operator berdasarkan nomor HP yang diketik user.
// Menggantikan tombol nominal yang tadinya HARDCODE manual di index-6.html.
// ---------------------------------------------------------------------

// Produk yang namanya mengandung kata-kata ini bukan pulsa murni (paket data/kuota),
// dibuang meski kolom category di Supabase salah di-tag 'pulsa'.
function isLikelyDataPackage(text) {
  return /\b(mb|gb|kuota|flash|internet|data)\b/i.test(text || '');
}
// Ambil angka nominal dari nama produk, misal "Telkomsel 2.000" -> 2000.
function extractNominal(text) {
  const m = String(text || '').match(/(\d{1,3}(?:[.,]\d{3})+|\d+)/);
  if (!m) return null;
  return Number(m[1].replace(/[.,]/g, ''));
}

async function handleProductsPulsa(request, env, url) {
  const accountId = await requireAccount(request, env);
  if (!accountId) return json({ status: false, message: 'Silakan login dulu' }, 401);

  const phone = url.searchParams.get('phone') || '';
  const operator = detectOperator(phone);
  if (!operator) {
    return json({ status: false, message: 'Nomor tidak dikenali / operator tidak ditemukan', data: [] }, 200);
  }

  // category=pulsa & operator sesuai deteksi & is_active=true, urut dari harga termurah
  const rows = await sbSelect(
    env, 'h2h_products',
    `category=eq.pulsa&operator=eq.${encodeURIComponent(operator)}&is_active=eq.true&select=product_code,name,description,price,status&order=price.asc`
  );

  const filtered = (rows || [])
    .filter((r) => r.status === '1' || r.status === 1 || r.status === null) // status null dianggap normal, "0" biasanya gangguan
    .filter((r) => !isLikelyDataPackage(r.name) && !isLikelyDataPackage(r.description)); // buang paket data yang ke-tag salah

  // Dedup per nominal: kalau beberapa SKU jual nominal yang sama, ambil yang paling murah saja.
  const byNominal = new Map();
  for (const r of filtered) {
    const nominal = extractNominal(r.name) ?? extractNominal(r.description);
    const key = nominal != null ? nominal : `code:${r.product_code}`; // fallback kalau nominal nggak kebaca, jangan digabung sembarangan
    const price = Number(r.price);
    const existing = byNominal.get(key);
    if (!existing || price < existing.price) {
      byNominal.set(key, {
        product_code: r.product_code,
        label: r.name || r.description,
        price,
        nominal: nominal != null ? nominal : undefined,
      });
    }
  }
  const list = Array.from(byNominal.values()).sort((a, b) => a.price - b.price);

  return json({ status: true, operator, data: list });
}

// ---------------------------------------------------------------------
// NEW: GET /products?category=data|pln|pdam|bpjs|...&phone=08xx (opsional)
// Generik untuk kategori h2h_products APAPUN selain pulsa (yang punya endpoint
// khusus di atas karena butuh deteksi operator + dedup nominal + filter data-package).
// Kalau category butuh operator (misal 'data', karena paket data juga per-operator),
// kirim query 'phone' juga -> operator dideteksi dan dipakai buat filter.
// Kalau category nggak butuh operator (PLN prabayar, dll), 'phone' boleh dikosongkan.
// PENTING: ini baru cocok buat kategori yang produknya berupa daftar nominal tetap
// (kayak pulsa/token PLN). Untuk PDAM/BPJS/tagihan pascabayar yang butuh CEK TAGIHAN
// dulu (inquiry) sebelum bayar, endpoint ini TIDAK cukup — perlu endpoint inquiry
// terpisah yang manggil H2H.id, belum dibuat di sini karena format inquiry-nya beda
// per produk (lihat dokumentasi H2H.id untuk endpoint inquiry sebelum dikerjakan).
// ---------------------------------------------------------------------
async function handleProductsGeneric(request, env, url) {
  const accountId = await requireAccount(request, env);
  if (!accountId) return json({ status: false, message: 'Silakan login dulu' }, 401);

  const category = (url.searchParams.get('category') || '').trim();
  if (!category) return json({ status: false, message: 'category wajib diisi' }, 400);
  if (category === 'pulsa') return json({ status: false, message: 'Pakai /products/pulsa untuk kategori ini' }, 400);

  // 'operator' bisa dikirim LANGSUNG (misal ?operator=DANA untuk e_wallet, ?operator=Mobile%20Legends
  // untuk voucher_game) — dipakai apa adanya, TIDAK dideteksi dari nomor telepon.
  // 'phone' dipakai HANYA kalau kategori ini butuh deteksi operator dari nomor HP (paket_data, paket_telp_sms).
  const explicitOperator = url.searchParams.get('operator');
  const phone = url.searchParams.get('phone') || '';
  let operator = explicitOperator || (phone ? detectOperator(phone) : null);
  if (!explicitOperator && phone && !operator) {
    return json({ status: false, message: 'Nomor tidak dikenali / operator tidak ditemukan', data: [] }, 200);
  }

  let query = `category=eq.${encodeURIComponent(category)}&is_active=eq.true&select=product_code,name,description,price,status&order=price.asc`;
  if (operator) query += `&operator=eq.${encodeURIComponent(operator)}`;

  const rows = await sbSelect(env, 'h2h_products', query);

  const filtered = (rows || []).filter((r) => r.status === '1' || r.status === 1 || r.status === null);

  // Dedup per nominal juga di sini, sama seperti pulsa (kalau ada beberapa SKU nominal sama).
  const byNominal = new Map();
  for (const r of filtered) {
    const nominal = extractNominal(r.name) ?? extractNominal(r.description);
    const key = nominal != null ? nominal : `code:${r.product_code}`;
    const price = Number(r.price);
    const existing = byNominal.get(key);
    if (!existing || price < existing.price) {
      byNominal.set(key, {
        product_code: r.product_code,
        label: r.name || r.description,
        price,
        nominal: nominal != null ? nominal : undefined,
      });
    }
  }
  const list = Array.from(byNominal.values()).sort((a, b) => a.price - b.price);

  return json({ status: true, category, operator: operator || null, data: list });
}

// ---------------------------------------------------------------------
// NEW: GET /products/operators?category=xxx
// Daftar nilai 'operator' yang BENERAN ADA & AKTIF di h2h_products untuk kategori ini.
// Dipakai buat bikin chip pilihan provider (DANA/OVO/GoPay/dll) atau game (Mobile Legends/
// Free Fire/dll) secara OTOMATIS dari database, bukan hardcode manual di frontend — jadi
// kalau H2H nambah/hapus provider, tinggal update Supabase, nggak perlu ubah kode.
// ---------------------------------------------------------------------
async function handleProductsOperators(request, env, url) {
  const accountId = await requireAccount(request, env);
  if (!accountId) return json({ status: false, message: 'Silakan login dulu' }, 401);

  const category = (url.searchParams.get('category') || '').trim();
  if (!category) return json({ status: false, message: 'category wajib diisi' }, 400);

  const rows = await sbSelect(
    env, 'h2h_products',
    `category=eq.${encodeURIComponent(category)}&is_active=eq.true&select=operator`
  );
  const seen = new Set();
  const operators = [];
  for (const r of rows || []) {
    const op = (r.operator || '').trim();
    if (op && !seen.has(op)) { seen.add(op); operators.push(op); }
  }
  operators.sort((a, b) => a.localeCompare(b));

  return json({ status: true, category, data: operators });
}

// ---------------------------------------------------------------------
// POST /trx/pulsa
// ---------------------------------------------------------------------
async function handleTrxPulsa(req, env) {
  const accountId = await requireAccount(req, env);
  if (!accountId) return json({ status: false, message: 'Silakan login dulu' }, 401);

  const { product, dest, quantity, ref_id } = await req.json();
  if (!product || !dest) return json({ status: false, message: 'product dan dest wajib diisi' }, 400);

  const officialProduct = await getOfficialProduct(env, product);
  if (!officialProduct) return json({ status: false, message: 'Produk tidak ditemukan atau sedang tidak aktif.' }, 404);

  const isSmm = !!officialProduct.is_smm;
  const qty = isSmm ? Math.max(1, Number(quantity) || officialProduct.min_qty || 1) : 1;
  if (isSmm && officialProduct.min_qty && qty < officialProduct.min_qty) {
    return json({ status: false, message: `Jumlah minimal ${officialProduct.min_qty}.` }, 400);
  }
  if (isSmm && officialProduct.max_qty && qty > officialProduct.max_qty) {
    return json({ status: false, message: `Jumlah maksimal ${officialProduct.max_qty}.` }, 400);
  }

  const price = isSmm ? Math.ceil((Number(officialProduct.price_per_1k) || 0) * qty / 1000) : Number(officialProduct.price);
  if (!price || price <= 0) return json({ status: false, message: 'Harga produk tidak valid.' }, 400);

  const refID = ref_id || `FINPAY${Date.now()}${Math.floor(Math.random() * 1000)}`;

  // ---- Jalur ADMIN/OWNER: bebas biaya admin, TIDAK potong saldo FinPay ----
  // Transaksi langsung dieksekusi ke H2H.id pakai kredensial master (sama seperti user biasa),
  // tapi account_balances FinPay punya admin sama sekali nggak disentuh — karena buat admin,
  // "saldo" yang relevan adalah saldo deposit H2H.id itu sendiri (dicek di GET /balance).
  if (await isAdminAccount(env, accountId)) {
    await upsertH2HTransaction(env, {
      ref_id: refID, account_id: accountId, order_type: isSmm ? 'smm' : 'regular',
      product_code: product, dest, quantity: qty, amount: price, payment_method: 'h2h_saldo_admin', status: 'pending',
    });
    let h2hAdmin;
    try {
      const creds = await getH2HConfig(env);
      h2hAdmin = await h2hOrder(env, creds, { product, isSmm, dest, quantity: qty, refID });
    } catch (err) {
      await upsertH2HTransaction(env, { ref_id: refID, status: 'failed', provider_message: String(err) });
      return json({ status: false, message: 'Gagal menghubungi H2H: ' + String(err) }, 502);
    }
    if (!h2hAdmin.ok) {
      await upsertH2HTransaction(env, { ref_id: refID, status: 'failed', provider_message: h2hAdmin.data.message || 'Order ditolak H2H' });
      return json({ status: false, message: h2hAdmin.data.message || 'Transaksi gagal' }, 400);
    }
    await upsertH2HTransaction(env, { ref_id: refID, status: 'success', serial_number: h2hAdmin.data.data && h2hAdmin.data.data.sn, provider_message: h2hAdmin.data.message || null });
    return json({ status: true, message: 'Transaksi berhasil (admin, saldo H2H.id)', data: h2hAdmin.data.data });
  }

  // Biaya admin Rp250 (sama seperti yang ditampilkan di frontend) HANYA berlaku untuk user biasa.
  // Bukan margin ke H2H.id — H2H tetap dibayar sebesar `price` asli, selisihnya jadi pendapatan FinPay.
  const CONSUMER_ADMIN_FEE = 250;
  const chargedPrice = price + CONSUMER_ADMIN_FEE;

  const [deducted] = await sbRpc(env, 'deduct_balance', { p_account_id: accountId, p_amount: chargedPrice });
  if (!deducted) return json({ status: false, message: 'Saldo tidak mencukupi' }, 400);

  await upsertH2HTransaction(env, {
    ref_id: refID, account_id: accountId, order_type: isSmm ? 'smm' : 'regular',
    product_code: product, dest, quantity: qty, amount: chargedPrice, payment_method: 'saldo', status: 'pending',
  });

  let h2h;
  try {
    const creds = await getH2HConfig(env);
    h2h = await h2hOrder(env, creds, { product, isSmm, dest, quantity: qty, refID });
  } catch (err) {
    await sbRpc(env, 'add_balance', { p_account_id: accountId, p_amount: chargedPrice });
    await upsertH2HTransaction(env, { ref_id: refID, status: 'failed', provider_message: String(err), refund_required: false, refunded: true });
    await sbInsert(env, 'balance_mutations', { account_id: accountId, type: 'payment', amount: -chargedPrice, balance_after: null, ref_id: refID, product_code: product, status: 'failed', description: String(err) });
    return json({ status: false, message: 'Gagal menghubungi H2H, saldo dikembalikan' }, 502);
  }

  if (!h2h.ok) {
    await sbRpc(env, 'add_balance', { p_account_id: accountId, p_amount: chargedPrice });
    await upsertH2HTransaction(env, { ref_id: refID, status: 'failed', provider_message: h2h.data.message || 'Order ditolak H2H', refund_required: false, refunded: true });
    await sbInsert(env, 'balance_mutations', { account_id: accountId, type: 'payment', amount: -chargedPrice, balance_after: null, ref_id: refID, product_code: product, status: 'failed', description: h2h.data.message || 'Order ditolak H2H' });
    return json({ status: false, message: h2h.data.message || 'Transaksi gagal, saldo dikembalikan' }, 400);
  }

  const [balanceRow] = await sbSelect(env, 'account_balances', `account_id=eq.${accountId}&select=balance`);
  await upsertH2HTransaction(env, { ref_id: refID, status: 'success', serial_number: h2h.data.data && h2h.data.data.sn, provider_message: h2h.data.message || null });
  await sbInsert(env, 'balance_mutations', {
    account_id: accountId, type: 'payment', amount: -chargedPrice, balance_after: balanceRow ? balanceRow.balance : null,
    ref_id: refID, h2h_invoice: h2h.data.data && h2h.data.data.sn, product_code: product, status: 'success',
    description: officialProduct.description || officialProduct.operator,
  });

  return json({ status: true, message: 'Transaksi berhasil', data: h2h.data.data });
}

// ---------------------------------------------------------------------
// PIN + Wallet
// ---------------------------------------------------------------------
async function handleVerifyPin(request, env) {
  const accountId = await requireAccount(request, env);
  if (!accountId) return json({ status: false, message: 'Sesi tidak valid, ulangi login.' }, 401);
  const { pin } = await request.json().catch(() => ({}));
  if (!pin) return json({ status: false, message: 'PIN wajib diisi' }, 400);
  const [account] = await sbSelect(env, 'accounts', `id=eq.${accountId}&select=pin_hash`);
  if (!account || !account.pin_hash) return json({ status: false, message: 'Akun ini belum punya PIN.' }, 400);
  const ok = await verifyPin(pin, account.pin_hash);
  if (!ok) return json({ status: false, message: 'PIN salah, coba lagi.' }, 400);
  return json({ status: true, message: 'PIN benar' });
}

async function handleWalletMyCode(request, env) {
  const accountId = await requireAccount(request, env);
  if (!accountId) return json({ status: false, message: 'Silakan login dulu' }, 401);
  const code = await sbRpc(env, 'ensure_wallet_code', { p_account_id: accountId });
  return json({ status: true, data: { wallet_code: code } });
}

async function handleWalletLookup(request, env, url) {
  const accountId = await requireAccount(request, env);
  if (!accountId) return json({ status: false, message: 'Silakan login dulu' }, 401);
  const code = url.searchParams.get('code');
  const phoneRaw = url.searchParams.get('phone');
  if (!code && !phoneRaw) return json({ status: false, message: 'code atau phone wajib diisi' }, 400);
  const filter = code ? `wallet_code=eq.${encodeURIComponent(code)}` : `phone_number=eq.${normalizePhone(phoneRaw)}`;
  const [receiver] = await sbSelect(env, 'accounts', `${filter}&select=id,name,wallet_code`);
  if (!receiver) return json({ status: false, message: code ? 'Kode tidak ditemukan' : 'Nomor HP tidak terdaftar di FinPay' }, 404);
  if (receiver.id === accountId) return json({ status: false, message: 'Tidak bisa kirim ke diri sendiri' }, 400);
  return json({ status: true, data: { account_id: receiver.id, name: receiver.name || 'Pengguna FinPay', wallet_code: receiver.wallet_code } });
}

async function handleWalletTransfer(request, env) {
  const accountId = await requireAccount(request, env);
  if (!accountId) return json({ status: false, message: 'Silakan login dulu' }, 401);
  const idemKey = request.headers.get('Idempotency-Key');
  if (!idemKey) return json({ status: false, message: 'Idempotency-Key wajib dikirim' }, 400);
  const [existing] = await sbSelect(env, 'wallet_transfers', `idempotency_key=eq.${encodeURIComponent(idemKey)}&select=*`);
  if (existing) return json({ status: true, duplicate: true, message: 'Transfer ini sudah pernah diproses', data: existing });

  const body = await request.json().catch(() => ({}));
  const { to_code, to_phone, note } = body;
  const amount = Number(body.amount);
  if ((!to_code && !to_phone) || !amount || amount < 1000) return json({ status: false, message: 'to_code/to_phone wajib diisi dan amount minimal Rp1.000' }, 400);

  const filter = to_code ? `wallet_code=eq.${encodeURIComponent(to_code)}` : `phone_number=eq.${normalizePhone(to_phone)}`;
  const [receiver] = await sbSelect(env, 'accounts', `${filter}&select=id,name`);
  if (!receiver) return json({ status: false, message: to_code ? 'Kode tidak ditemukan' : 'Nomor HP tidak terdaftar di FinPay' }, 404);
  if (receiver.id === accountId) return json({ status: false, message: 'Tidak bisa kirim ke diri sendiri' }, 400);

  const [deducted] = await sbRpc(env, 'deduct_balance', { p_account_id: accountId, p_amount: amount });
  if (!deducted) return json({ status: false, message: 'Saldo tidak mencukupi' }, 400);

  try {
    await sbRpc(env, 'add_balance', { p_account_id: receiver.id, p_amount: amount });
  } catch (err) {
    await sbRpc(env, 'add_balance', { p_account_id: accountId, p_amount: amount });
    return json({ status: false, message: 'Transfer gagal, saldo kamu tidak terpotong' }, 500);
  }

  const inserted = await sbInsert(env, 'wallet_transfers', { idempotency_key: idemKey, sender_account_id: accountId, receiver_account_id: receiver.id, amount, note: note || null });
  await sbInsert(env, 'balance_mutations', { account_id: accountId, type: 'payment', amount: -amount, balance_after: null, description: `Transfer ke ${receiver.name || 'Pengguna FinPay'}`, status: 'success' });
  await sbInsert(env, 'balance_mutations', { account_id: receiver.id, type: 'topup', amount: amount, balance_after: null, description: 'Transfer masuk', status: 'success' });

  return json({ status: true, message: `Berhasil kirim Rp${amount.toLocaleString('id-ID')} ke ${receiver.name || 'Pengguna FinPay'}`, data: inserted });
}

// ---------------------------------------------------------------------
// Top Up saldo — Sakurupiah + QRIS.pw
// ---------------------------------------------------------------------
async function handleTopupMethods(request, env) {
  const accountId = await requireAccount(request, env);
  if (!accountId) return json({ status: false, message: 'Silakan login dulu' }, 401);

  const list = [];

  // 1) Channel dari Sakurupiah (kalau merchant-nya sudah aktif, otomatis muncul)
  try {
    const sk = await sakurupiahListPayment(env);
    if (sk.ok) {
      const allowed = CONFIG.TOPUP_ALLOWED_METHODS;
      (sk.data.data || [])
        .filter((m) => m.status === 'Aktif')
        .filter((m) => !allowed.length || allowed.includes(m.kode))
        .forEach((m) => {
          list.push({
            kode: m.kode, nama: m.nama, minimal: Number(m.minimal), maksimal: Number(m.maksimal),
            biaya: m.biaya, percent: m.percent, tipe: m.tipe, logo: m.logo, gateway: 'sakurupiah',
          });
        });
    }
  } catch (err) {
    // Sakurupiah lagi bermasalah/merchant belum aktif -> lewati, jangan gagalkan seluruh response
  }

  // 2) QRIS dari QRIS.pw (worker terpisah) — selalu ditawarkan sebagai opsi QRIS
  list.push({
    kode: 'QRISPW', nama: 'QRIS (QRIS.pw)', minimal: 1000, maksimal: 10000000,
    biaya: 0, percent: 0, tipe: 'DIRECT', logo: null, gateway: 'qrispw',
  });

  return json({ status: true, data: list });
}

async function handleTopupCreate(request, env) {
  const accountId = await requireAccount(request, env);
  if (!accountId) return json({ status: false, message: 'Silakan login dulu' }, 401);

  const { method, amount } = await request.json().catch(() => ({}));
  const amt = Number(amount);
  if (!method || !amt || amt < 1000) return json({ status: false, message: 'method dan amount (minimal Rp1.000) wajib diisi' }, 400);

  const [account] = await sbSelect(env, 'accounts', `id=eq.${accountId}&select=name,phone_number`);
  if (!account) return json({ status: false, message: 'Akun tidak ditemukan' }, 404);

  const isQrispw = method === 'QRISPW';
  const merchantRef = isQrispw
    ? `FPQPW${Date.now()}${Math.floor(Math.random() * 1000)}`
    : `FPTOPUP${Date.now()}${Math.floor(Math.random() * 1000)}`;

  const topupRow = await sbInsert(env, 'topups', {
    account_id: accountId, merchant_ref: merchantRef, method, amount: amt, status: 'pending',
    gateway: isQrispw ? 'qrispw' : 'sakurupiah',
  });

  if (isQrispw) {
    // ---------- Jalur QRIS.pw (worker terpisah) ----------
    let qp;
    try {
      qp = await qrispwCreateInvoice(env, { amount: amt, merchantRef, name: account.name, phone: account.phone_number });
    } catch (err) {
      await sbUpdate(env, 'topups', `id=eq.${topupRow.id}`, { status: 'failed', provider_message: String(err) });
      return json({ status: false, message: 'Gagal menghubungi QRIS.pw' }, 502);
    }
    if (!qp.ok) {
      await sbUpdate(env, 'topups', `id=eq.${topupRow.id}`, { status: 'failed', provider_message: qp.data.error || 'Gagal membuat invoice QRIS.pw' });
      return json({ status: false, message: qp.data.error || 'Gagal membuat invoice QRIS top up' }, 400);
    }
    await sbUpdate(env, 'topups', `id=eq.${topupRow.id}`, {
      trx_id: qp.data.transaction_id,
      payment_kode: 'QRISPW',
      qr_string: qp.data.qris_string || null,
      checkout_url: qp.data.qris_url || null,
      expired_at: qp.data.expires_at || null,
      charged_amount: amt,
      fee_amount: 0,
    });
    return json({
      status: true, message: 'Invoice QRIS berhasil dibuat',
      data: {
        merchant_ref: merchantRef, trx_id: qp.data.transaction_id, method: 'QRISPW',
        amount: amt, fee: 0, total: amt,
        qr_string: qp.data.qris_string || null, payment_no: null,
        checkout_url: qp.data.qris_url || null, expired_at: qp.data.expires_at || null,
      },
    });
  }

  // ---------- Jalur Sakurupiah (default, seperti sebelumnya) ----------
  let sk;
  try {
    sk = await sakurupiahCreateInvoice(env, {
      method, name: account.name, phone: account.phone_number, amount: amt,
      merchantFee: 2, merchantRef, expired: 1,
    });
  } catch (err) {
    await sbUpdate(env, 'topups', `id=eq.${topupRow.id}`, { status: 'failed', provider_message: String(err) });
    return json({ status: false, message: 'Gagal menghubungi payment gateway' }, 502);
  }
  if (!sk.ok) {
    await sbUpdate(env, 'topups', `id=eq.${topupRow.id}`, { status: 'failed', provider_message: sk.data.message || 'Gagal membuat invoice' });
    return json({ status: false, message: sk.data.message || 'Gagal membuat invoice top up' }, 400);
  }
  const inv = (sk.data.data || [])[0] || {};
  const chargedAmount = Number(inv.total) || amt;
  const feeAmount = Math.max(0, chargedAmount - amt);
  await sbUpdate(env, 'topups', `id=eq.${topupRow.id}`, {
    trx_id: inv.trx_id, payment_kode: inv.payment_kode, checkout_url: inv.checkout_url,
    qr_string: inv.qr || null, payment_no: inv.payment_no || null, expired_at: inv.expired || null,
    charged_amount: chargedAmount, fee_amount: feeAmount,
  });
  return json({
    status: true, message: 'Invoice berhasil dibuat',
    data: {
      merchant_ref: merchantRef, trx_id: inv.trx_id, method: inv.payment_kode, amount: amt,
      fee: feeAmount, total: chargedAmount, qr_string: inv.qr || null, payment_no: inv.payment_no || null,
      checkout_url: inv.checkout_url || null, expired_at: inv.expired || null,
    },
  });
}

async function handleTopupStatus(request, env, merchantRef) {
  const accountId = await requireAccount(request, env);
  if (!accountId) return json({ status: false, message: 'Silakan login dulu' }, 401);

  const [row] = await sbSelect(env, 'topups', `merchant_ref=eq.${encodeURIComponent(merchantRef)}&account_id=eq.${accountId}&select=*`);
  if (!row) return json({ status: false, message: 'Top up tidak ditemukan' }, 404);

  if (row.status === 'pending' && row.trx_id) {
    try {
      if (row.gateway === 'qrispw') {
        const qp = await qrispwCheckStatus(env, row.trx_id);
        const remoteStatus = qp.ok ? String(qp.data.status || '').toLowerCase() : null;
        if ((remoteStatus === 'paid' || remoteStatus === 'success') && row.status !== 'berhasil') {
          await creditTopup(env, row);
          row.status = 'berhasil';
        } else if (remoteStatus === 'expired') {
          await sbUpdate(env, 'topups', `id=eq.${row.id}`, { status: 'expired' });
          row.status = 'expired';
        }
      } else {
        const sk = await sakurupiahCheckStatus(env, row.trx_id);
        const remoteStatus = sk.ok && (sk.data.data || [])[0] && (sk.data.data || [])[0].status;
        if (remoteStatus === 'berhasil' && row.status !== 'berhasil') {
          await creditTopup(env, row);
          row.status = 'berhasil';
        } else if (remoteStatus === 'expired') {
          await sbUpdate(env, 'topups', `id=eq.${row.id}`, { status: 'expired' });
          row.status = 'expired';
        }
      }
    } catch (err) {
      // Abaikan error cek status manual, biarkan webhook yang urus nanti.
    }
  }

  return json({ status: true, data: { status: row.status, merchant_ref: row.merchant_ref, amount: row.amount } });
}

async function creditTopup(env, topupRow) {
  const [fresh] = await sbSelect(env, 'topups', `id=eq.${topupRow.id}&select=status`);
  if (fresh && fresh.status === 'berhasil') return;
  await sbRpc(env, 'add_balance', { p_account_id: topupRow.account_id, p_amount: topupRow.amount });
  const [balanceRow] = await sbSelect(env, 'account_balances', `account_id=eq.${topupRow.account_id}&select=balance`);
  await sbUpdate(env, 'topups', `id=eq.${topupRow.id}`, { status: 'berhasil' });
  await sbInsert(env, 'balance_mutations', {
    account_id: topupRow.account_id, type: 'topup', amount: topupRow.amount,
    balance_after: balanceRow ? balanceRow.balance : null, ref_id: topupRow.merchant_ref,
    status: 'success', description: `Top up via ${topupRow.method}`,
  });
}

async function handleTopupCallback(request, env) {
  const rawBody = await request.text();
  const callbackSignature = request.headers.get('X-Callback-Signature') || '';
  const callbackEvent = request.headers.get('X-Callback-Event') || '';
  const expectedSignature = await hmacSha256Hex(rawBody, env.SAKURUPIAH_API_KEY);
  if (callbackSignature !== expectedSignature) return json({ success: false, message: 'Invalid signature' }, 401);

  let data;
  try { data = JSON.parse(rawBody); } catch (err) { return json({ success: false, message: 'Invalid data send by payment gateway' }, 400); }
  if (callbackEvent !== 'payment_status') return json({ success: false, message: `Unrecognized callback event: ${callbackEvent}` }, 400);

  const merchantRef = data.merchant_ref;
  const [topupRow] = await sbSelect(env, 'topups', `merchant_ref=eq.${encodeURIComponent(merchantRef)}&select=*`);
  if (!topupRow) return json({ success: true, message: 'merchant_ref tidak dikenali, diabaikan' });

  try {
    if (data.status === 'berhasil') { await creditTopup(env, topupRow); return json({ success: true, message: 'Payment status berhasil' }); }
    if (data.status === 'expired') { await sbUpdate(env, 'topups', `id=eq.${topupRow.id}`, { status: 'expired' }); return json({ success: true, message: 'Payment status expired' }); }
    if (data.status === 'pending') return json({ success: true, message: 'Payment status pending' });
    throw new Error('Error Data Status Callback');
  } catch (err) {
    return json({ success: false, message: String(err) }, 500);
  }
}

// ---------------------------------------------------------------------
// NEW: Webhook dari QRIS.pw (dipanggil LANGSUNG oleh qris.pw ke FinPay,
// bukan lewat worker QRIS.pw — jadi tidak tergantung worker itu online atau nggak)
// Payload sesuai dokumentasi qris.pw:
// { transaction_id, order_id, amount, status, paid_at, timestamp, signature }
// signature = hash_hmac('sha256', json_encode(payload_tanpa_signature), webhook_secret)
// ---------------------------------------------------------------------
async function handleTopupQrispwCallback(request, env) {
  const rawBody = await request.text();
  let data;
  try { data = JSON.parse(rawBody); } catch (err) { return json({ success: false, message: 'invalid json' }, 400); }

  const { signature, ...payloadWithoutSig } = data;
  const expectedSignature = await hmacSha256Hex(JSON.stringify(payloadWithoutSig), env.QRISPW_WEBHOOK_SECRET);
  if (!signature || signature !== expectedSignature) {
    return json({ success: false, message: 'Invalid signature' }, 401);
  }

  const merchantRef = data.order_id;
  const [topupRow] = await sbSelect(env, 'topups', `merchant_ref=eq.${encodeURIComponent(merchantRef)}&select=*`);
  if (!topupRow) return json({ success: true, message: 'order_id tidak dikenali, diabaikan' });

  const status = String(data.status || '').toLowerCase();
  try {
    if (status === 'paid' || status === 'success') { await creditTopup(env, topupRow); return json({ success: true, message: 'Payment status berhasil' }); }
    if (status === 'expired') { await sbUpdate(env, 'topups', `id=eq.${topupRow.id}`, { status: 'expired' }); return json({ success: true, message: 'Payment status expired' }); }
    if (status === 'pending') return json({ success: true, message: 'Payment status pending' });
    if (status === 'failed') { await sbUpdate(env, 'topups', `id=eq.${topupRow.id}`, { status: 'failed' }); return json({ success: true, message: 'Payment status failed' }); }
    return json({ success: true, message: 'status tidak dikenal, diabaikan' });
  } catch (err) {
    return json({ success: false, message: String(err) }, 500);
  }
}

// ---------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------
export default {
  async fetch(request, env) {
    env = { ...CONFIG, ...env };

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, Idempotency-Key',
        },
      });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (path === '/' && request.method === 'GET') {
        return json({
          status: true,
          service: 'finpay-backend',
          message: 'FinPay backend is running',
          docs: 'Lihat komentar di bagian atas file worker untuk daftar route.',
        });
      }
      if (path === '/otp/start' && request.method === 'POST') return await handleOtpStart(request, env);
      if (path === '/otp/verify' && request.method === 'POST') return await handleOtpVerify(request, env);
      if (path === '/webhook/loginwa' && request.method === 'POST') return json({ status: true });
      if (path === '/auth/verify-pin' && request.method === 'POST') return await handleVerifyPin(request, env);
      if (path.startsWith('/balance/') && request.method === 'GET') return await handleGetBalance(path.split('/balance/')[1], env);
      if (path === '/trx/pulsa' && request.method === 'POST') return await handleTrxPulsa(request, env);
      if (path === '/products/pulsa' && request.method === 'GET') return await handleProductsPulsa(request, env, url);
      if (path === '/products/operators' && request.method === 'GET') return await handleProductsOperators(request, env, url);
      if (path === '/products' && request.method === 'GET') return await handleProductsGeneric(request, env, url);
      if (path === '/wallet/my-code' && request.method === 'GET') return await handleWalletMyCode(request, env);
      if (path === '/wallet/lookup' && request.method === 'GET') return await handleWalletLookup(request, env, url);
      if (path === '/wallet/transfer' && request.method === 'POST') return await handleWalletTransfer(request, env);
      if (path === '/topup/methods' && request.method === 'GET') return await handleTopupMethods(request, env);
      if (path === '/topup/create' && request.method === 'POST') return await handleTopupCreate(request, env);
      if (path.startsWith('/topup/status/') && request.method === 'GET') return await handleTopupStatus(request, env, path.split('/topup/status/')[1]);
      if (path === '/topup/callback' && request.method === 'POST') return await handleTopupCallback(request, env);
      if (path === '/topup/qris-callback' && request.method === 'POST') return await handleTopupQrispwCallback(request, env);

      return json({ status: false, message: 'Not found' }, 404);
    } catch (err) {
      return json({ status: false, message: 'Internal error', detail: String(err) }, 500);
    }
  },
};

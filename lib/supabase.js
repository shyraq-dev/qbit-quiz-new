// lib/supabase.js — server-side only, credentials жасырын
const SB_URL = process.env.SUPABASE_URL;
const SB_KEY = process.env.SUPABASE_SERVICE_KEY; // service_role key!

export function sbHeaders(extra = {}) {
  return {
    'Content-Type': 'application/json',
    'apikey': SB_KEY,
    'Authorization': 'Bearer ' + SB_KEY,
    ...extra,
  };
}

export async function sbSelect(table, qs = '') {
  const r = await fetch(`${SB_URL}/rest/v1/${table}?${qs}`, {
    headers: sbHeaders(),
  });
  if (!r.ok) { const t = await r.text(); throw new Error(t); }
  return r.json();
}

export async function sbInsert(table, body, prefer = 'return=representation') {
  const r = await fetch(`${SB_URL}/rest/v1/${table}`, {
    method: 'POST',
    headers: sbHeaders({ 'Prefer': prefer }),
    body: JSON.stringify(body),
  });
  if (!r.ok) { const t = await r.text(); throw new Error(t); }
  return r.json();
}

export async function sbUpsert(table, body, conflict, prefer = 'return=representation') {
  const r = await fetch(`${SB_URL}/rest/v1/${table}`, {
    method: 'POST',
    headers: sbHeaders({
      'Prefer': `resolution=merge-duplicates,${prefer}`,
      'on-conflict': conflict,
    }),
    body: JSON.stringify(body),
  });
  if (!r.ok) { const t = await r.text(); throw new Error(t); }
  return r.json();
}

export async function sbUpdate(table, body, filter) {
  const r = await fetch(`${SB_URL}/rest/v1/${table}?${filter}`, {
    method: 'PATCH',
    headers: sbHeaders({ 'Prefer': 'return=representation' }),
    body: JSON.stringify(body),
  });
  if (!r.ok) { const t = await r.text(); throw new Error(t); }
  return r.json();
}

export async function sbDelete(table, filter) {
  const r = await fetch(`${SB_URL}/rest/v1/${table}?${filter}`, {
    method: 'DELETE',
    headers: sbHeaders({ 'Prefer': 'return=representation' }),
  });
  if (!r.ok) { const t = await r.text(); throw new Error(t); }
  return r.json();
}

export async function sbRpc(fn, args = {}) {
  const r = await fetch(`${SB_URL}/rest/v1/rpc/${fn}`, {
    method: 'POST',
    headers: sbHeaders(),
    body: JSON.stringify(args),
  });
  if (!r.ok) { const t = await r.text(); throw new Error(t); }
  return r.json();
}

// CORS helper
export function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

export function ok(res, data) { res.status(200).json({ ok: true, data }); }
export function err(res, msg, code = 400) { res.status(code).json({ ok: false, error: msg }); }
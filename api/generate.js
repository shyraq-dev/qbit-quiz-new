// api/generate.js — AI сұрақ генерациясы
// 1. HuggingFace AlemLLM (astanahub/alemllm)
// 2. Gemini fallback
import { cors, ok, err } from '../lib/supabase.js';
import { verifySessionToken } from '../lib/session.js';

const HF_TOKEN   = process.env.HF_TOKEN;
const GEMINI_KEY = process.env.GEMINI_KEY;

const SYSTEM_PROMPT = `Сен QBit Quiz платформасының AI-сұрақ генераторысың.
Тек JSON массивін қайтар, басқа ешнәрсе жоқ:
[{"text":"...","options":["...","...","...","..."],"correct":0,"explanation":"..."}]
Ережелер: тек JSON, markdown жоқ, correct=0-3 индекс, тек қазақша.`;

export default async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return err(res, 'POST only', 405);

  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!verifySessionToken(token)) return err(res, 'unauthorized', 401);

  const { topic, text, count = 5, difficulty = 'орташа' } = req.body || {};
  if (!topic && !text) return err(res, 'topic or text required', 400);

  const prompt = text
    ? `Мына мәтін бойынша ${count} сұрақ жаса (${difficulty}):\n\n${text.slice(0, 2000)}`
    : `"${topic}" тақырыбы бойынша ${count} ${difficulty} сұрақ жаса.`;

  // 1. AlemLLM — HuggingFace Inference API (text-generation pipeline)
  if (HF_TOKEN) {
    try { return ok(res, await callAlemLLM(prompt)); }
    catch (e) { console.warn('[AlemLLM]', e.message); }
  }

  // 2. Gemini fallback
  if (GEMINI_KEY) {
    try { return ok(res, await callGemini(prompt)); }
    catch (e) { console.warn('[Gemini]', e.message); }
  }

  return err(res, 'ai_unavailable', 503);
}

// ── AlemLLM ──────────────────────────────────────────────
// astanahub/alemllm — text-generation (Inference API v2)
async function callAlemLLM(prompt) {
  const r = await fetch(
    'https://api-inference.huggingface.co/models/astanahub/alemllm',
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${HF_TOKEN}`,
        'Content-Type': 'application/json',
        'x-wait-for-model': 'true',
      },
      body: JSON.stringify({
        inputs: `<s>[INST] ${SYSTEM_PROMPT}\n\n${prompt} [/INST]`,
        parameters: {
          max_new_tokens: 2048,
          temperature: 0.7,
          return_full_text: false,
          do_sample: true,
        },
      }),
    }
  );
  if (!r.ok) {
    const t = await r.text();
    throw new Error(`HF ${r.status}: ${t.slice(0, 200)}`);
  }
  const d = await r.json();
  const raw = Array.isArray(d) ? d[0]?.generated_text : d?.generated_text;
  if (!raw) throw new Error('HF empty response');
  return parse(raw);
}

// ── Gemini ────────────────────────────────────────────────
async function callGemini(prompt) {
  const r = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${GEMINI_KEY}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        system_instruction: { parts: [{ text: SYSTEM_PROMPT }] },
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.7, maxOutputTokens: 2048 },
      }),
    }
  );
  if (!r.ok) throw new Error(`Gemini ${r.status}`);
  const d = await r.json();
  const raw = d.candidates?.[0]?.content?.parts?.[0]?.text || '';
  return parse(raw);
}

// ── Parser ────────────────────────────────────────────────
function parse(raw) {
  const clean = raw.replace(/```json|```/g, '').trim();
  const m = clean.match(/\[[\s\S]*\]/);
  if (!m) throw new Error('no JSON array');
  const arr = JSON.parse(m[0]);
  if (!Array.isArray(arr) || !arr.length) throw new Error('empty array');
  return arr.map(q => ({
    text: String(q.text || q.question || '').trim(),
    options: Array.isArray(q.options) ? q.options.map(String) : [],
    correct: Number(q.correct ?? q.answer ?? 0),
    explanation: String(q.explanation || '').trim(),
  })).filter(q => q.text && q.options.length === 4);
}

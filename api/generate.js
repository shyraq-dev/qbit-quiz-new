// api/generate.js  — AI сұрақ генерациясы
// 1. HuggingFace AlemLLM (қазақша, негізгі)
// 2. Gemini API (server-side, жапсырма ретінде)
import { cors, ok, err } from '../lib/supabase.js';
import { verifySessionToken } from './auth.js';

const HF_TOKEN     = process.env.HF_TOKEN;       // HuggingFace token
const GEMINI_KEY   = process.env.GEMINI_KEY;      // Gemini API key
const ADMIN_ID     = process.env.ADMIN_ID;

const HF_MODEL = 'astanahub/alemllm';
const SYSTEM_PROMPT = `Сен QBit Quiz платформасының AI-сұрақ генераторысың.
Сенің міндетің: берілген тақырып бойынша қазақша тест сұрақтарын жасау.
Тек JSON массивін қайтар, басқа ешнәрсе жоқ. Мысал:
[
  {
    "text": "Сұрақ мәтіні",
    "options": ["A жауап", "B жауап", "C жауап", "D жауап"],
    "correct": 0,
    "explanation": "Түсіндірме"
  }
]
Ережелер:
- Тек JSON, markdown жоқ, кіріспе жоқ
- correct — дұрыс жауаптың индексі (0–3)
- Жауаптар нанымды, бірдей ұзындықта
- Тек қазақша`;

export default async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return err(res, 'POST only', 405);

  const token = req.headers.authorization?.replace('Bearer ', '');
  const session = token ? verifySessionToken(token) : null;
  if (!session) return err(res, 'unauthorized', 401);

  const { topic, count = 5, difficulty = 'орташа', mode = 'quiz', text } = req.body || {};
  if (!topic && !text) return err(res, 'topic or text required', 400);

  try {
    const questions = await generate({ topic, text, count, difficulty });
    return ok(res, questions);
  } catch (e) {
    console.error('[generate]', e.message);
    return err(res, e.message, 500);
  }
}

// ── Main generator ────────────────────────────────────────
async function generate({ topic, text, count, difficulty }) {
  const userPrompt = text
    ? `Мына мәтін бойынша ${count} сұрақ жаса (күрделілік: ${difficulty}):\n\n${text.slice(0, 2000)}`
    : `"${topic}" тақырыбы бойынша ${count} ${difficulty} деңгейлі сұрақ жаса.`;

  // 1. AlemLLM (HuggingFace Inference API)
  if (HF_TOKEN) {
    try {
      return await callAlemLLM(userPrompt);
    } catch (e) {
      console.warn('[AlemLLM failed]', e.message, '→ fallback Gemini');
    }
  }

  // 2. Gemini fallback
  if (GEMINI_KEY) {
    try {
      return await callGemini(userPrompt);
    } catch (e) {
      console.warn('[Gemini failed]', e.message);
    }
  }

  throw new Error('ai_unavailable');
}

// ── AlemLLM ──────────────────────────────────────────────
async function callAlemLLM(userPrompt) {
  const r = await fetch(
    `https://api-inference.huggingface.co/models/${HF_MODEL}/v1/chat/completions`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${HF_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: HF_MODEL,
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user',   content: userPrompt },
        ],
        max_tokens: 2000,
        temperature: 0.7,
        stream: false,
      }),
    }
  );
  if (!r.ok) throw new Error(`HF ${r.status}: ${await r.text()}`);
  const d = await r.json();
  const raw = d.choices?.[0]?.message?.content || '';
  return parseQuestions(raw);
}

// ── Gemini ────────────────────────────────────────────────
async function callGemini(userPrompt) {
  const r = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${GEMINI_KEY}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        system_instruction: { parts: [{ text: SYSTEM_PROMPT }] },
        contents: [{ parts: [{ text: userPrompt }] }],
        generationConfig: { temperature: 0.7, maxOutputTokens: 2000 },
      }),
    }
  );
  if (!r.ok) throw new Error(`Gemini ${r.status}: ${await r.text()}`);
  const d = await r.json();
  const raw = d.candidates?.[0]?.content?.parts?.[0]?.text || '';
  return parseQuestions(raw);
}

// ── Parser ────────────────────────────────────────────────
function parseQuestions(raw) {
  const clean = raw.replace(/```json|```/g, '').trim();
  // JSON массивін тап
  const match = clean.match(/\[[\s\S]*\]/);
  if (!match) throw new Error('parse_error: no JSON array found');
  const parsed = JSON.parse(match[0]);
  if (!Array.isArray(parsed) || !parsed.length) throw new Error('parse_error: empty array');
  return parsed.map(q => ({
    text: String(q.text || q.question || ''),
    options: Array.isArray(q.options) ? q.options.map(String) : [],
    correct: Number(q.correct ?? q.answer ?? 0),
    explanation: String(q.explanation || ''),
  })).filter(q => q.text && q.options.length === 4);
}

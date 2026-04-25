// api/tg-photos.js — Telegram Bot API арқылы қолданушының фотоларын алу
import { cors, ok, err } from '../lib/supabase.js';
import { verifySessionToken } from '../lib/session.js';

const BOT_TOKEN = process.env.BOT_TOKEN;

export default async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return err(res, 'POST only', 405);

  const token = req.headers.authorization?.replace('Bearer ', '');
  const session = token ? verifySessionToken(token) : null;
  if (!session) return err(res, 'unauthorized', 401);

  // Тек Telegram қолданушылары үшін
  if (!session.uid.startsWith('tg:')) {
    return ok(res, { photos: [] });
  }

  const tgId = session.uid.replace('tg:', '');

  if (!BOT_TOKEN) {
    return ok(res, { photos: [] });
  }

  try {
    // getUserProfilePhotos — барлық фотоларды алу
    const r = await fetch(
      `https://api.telegram.org/bot${BOT_TOKEN}/getUserProfilePhotos?user_id=${tgId}&limit=9`
    );
    const data = await r.json();

    if (!data.ok || !data.result?.photos?.length) {
      return ok(res, { photos: [] });
    }

    // Әр фото үшін ең үлкен нұсқасын алу
    const photoUrls = [];
    for (const photoSet of data.result.photos) {
      // Ең соңғы (ең үлкен) нұсқасы
      const largest = photoSet[photoSet.length - 1];
      const fileId = largest.file_id;

      // File path алу
      const fr = await fetch(
        `https://api.telegram.org/bot${BOT_TOKEN}/getFile?file_id=${fileId}`
      );
      const fd = await fr.json();

      if (fd.ok) {
        const url = `https://api.telegram.org/file/bot${BOT_TOKEN}/${fd.result.file_path}`;
        photoUrls.push(url);
      }
    }

    return ok(res, { photos: photoUrls });
  } catch (e) {
    console.error('[tg-photos]', e.message);
    return ok(res, { photos: [] }); // Қате болса бос қайтару
  }
}

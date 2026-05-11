const { cors, ok, err } = require('../lib/supabase.js');
const { verifySessionToken } = require('../lib/session.js');
const BOT_TOKEN = process.env.BOT_TOKEN || '';

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const session = verifySessionToken(token);
  if (!session) return err(res, 'unauthorized', 401);
  if (!session.uid.startsWith('tg:') || !BOT_TOKEN) return ok(res, { photos: [] });

  const tgId = session.uid.replace('tg:', '');
  try {
    const r = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/getUserProfilePhotos?user_id=${tgId}&limit=9`);
    const d = await r.json();
    if (!d.ok || !d.result?.photos?.length) return ok(res, { photos: [] });

    const urls = [];
    for (const set of d.result.photos) {
      const fid = set[set.length - 1].file_id;
      const fr = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/getFile?file_id=${fid}`);
      const fd = await fr.json();
      if (fd.ok) urls.push(`https://api.telegram.org/file/bot${BOT_TOKEN}/${fd.result.file_path}`);
    }
    return ok(res, { photos: urls });
  } catch (e) {
    return ok(res, { photos: [] });
  }
};

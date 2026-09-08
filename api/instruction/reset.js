const { getSupabase } = require('../../lib/supabase');
const { applyCors, checkAppSecret, verifyAdminToken } = require('../../lib/auth');

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== 'POST') { res.status(405).json({ ok: false, error: 'Methode non autorisee' }); return; }
  if (!checkAppSecret(req)) { res.status(401).json({ ok: false, error: 'Secret application invalide' }); return; }

  const session = verifyAdminToken(req);
  if (!session) { res.status(401).json({ ok: false, error: 'Session administrateur requise ou expiree.' }); return; }

  try {
    const supabase = getSupabase();
    const { error } = await supabase
      .from('instruction_state')
      .upsert({ id: 'main', fiches: [], updated_at: new Date().toISOString() });
    if (error) throw error;
    res.status(200).json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
};

const crypto = require('crypto');
const { getSupabase } = require('../../lib/supabase');
const { applyCors, checkAppSecret, issueAdminToken } = require('../../lib/auth');

function hashCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== 'POST') { res.status(405).json({ ok: false, error: 'Methode non autorisee' }); return; }
  if (!checkAppSecret(req)) { res.status(401).json({ ok: false, error: 'Secret application invalide' }); return; }

  try {
    const { email, code } = req.body || {};
    if (!email || !code) { res.status(400).json({ ok: false, error: 'Email et code requis' }); return; }

    const supabase = getSupabase();
    const { data: row } = await supabase
      .from('admin_codes')
      .select('*')
      .eq('email', email)
      .maybeSingle();

    if (!row) { res.status(200).json({ ok: false, error: 'Aucun code en attente pour cette adresse. Redemande un code.' }); return; }
    if (new Date(row.expires_at).getTime() < Date.now()) {
      await supabase.from('admin_codes').delete().eq('email', email);
      res.status(200).json({ ok: false, error: 'Code expire. Redemande un code.' });
      return;
    }
    if (hashCode(String(code)) !== row.code_hash) {
      res.status(200).json({ ok: false, error: 'Code incorrect.' });
      return;
    }

    await supabase.from('admin_codes').delete().eq('email', email);
    const token = issueAdminToken(email);
    res.status(200).json({ ok: true, token });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
};

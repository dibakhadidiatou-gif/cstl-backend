const { getSupabase } = require('../../lib/supabase');
const { applyCors, checkAppSecret, verifyAdminToken } = require('../../lib/auth');

// Gestion des administrateurs depuis l'application, sans passer par le SQL
// Editor de Supabase.
// - GET                              : liste des administrateurs
// - POST { action:'add', email }     : ajoute un administrateur
// - POST { action:'remove', email }  : retire un administrateur
// Reserve a un administrateur connecte, dont l'adresse figure TOUJOURS dans
// admin_emails (un admin retire ne peut plus gerer les autres, meme si son
// jeton de 24h n'a pas encore expire).

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

async function listAdmins(supabase) {
  const { data, error } = await supabase
    .from('admin_emails')
    .select('email, added_at')
    .order('added_at', { ascending: true });
  if (error) throw error;
  return data || [];
}

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (!checkAppSecret(req)) { res.status(401).json({ ok: false, error: 'Secret application invalide' }); return; }

  const session = verifyAdminToken(req);
  if (!session) { res.status(401).json({ ok: false, error: 'Session administrateur requise ou expiree.' }); return; }

  try {
    const supabase = getSupabase();

    const { data: stillAdmin } = await supabase
      .from('admin_emails')
      .select('email')
      .eq('email', session.email)
      .maybeSingle();
    if (!stillAdmin) { res.status(403).json({ ok: false, error: 'Cette adresse n\'est plus administrateur.' }); return; }

    if (req.method === 'GET') {
      res.status(200).json({ ok: true, admins: await listAdmins(supabase) });
      return;
    }

    if (req.method !== 'POST') { res.status(405).json({ ok: false, error: 'Methode non autorisee' }); return; }

    const { action } = req.body || {};
    const email = normalizeEmail(req.body && req.body.email);
    if (!EMAIL_RE.test(email)) { res.status(400).json({ ok: false, error: 'Adresse email invalide.' }); return; }

    if (action === 'add') {
      const { data: existing } = await supabase
        .from('admin_emails')
        .select('email')
        .eq('email', email)
        .maybeSingle();
      if (existing) { res.status(200).json({ ok: false, error: 'Cette adresse est deja administrateur.' }); return; }

      const { error } = await supabase.from('admin_emails').insert({ email });
      if (error) throw error;
      res.status(200).json({ ok: true, admins: await listAdmins(supabase) });
      return;
    }

    if (action === 'remove') {
      if (email === normalizeEmail(session.email)) {
        res.status(200).json({ ok: false, error: 'Tu ne peux pas retirer ta propre adresse.' });
        return;
      }
      const admins = await listAdmins(supabase);
      if (admins.length <= 1) { res.status(200).json({ ok: false, error: 'Il doit rester au moins un administrateur.' }); return; }

      const { error } = await supabase.from('admin_emails').delete().eq('email', email);
      if (error) throw error;
      await supabase.from('admin_codes').delete().eq('email', email);
      res.status(200).json({ ok: true, admins: await listAdmins(supabase) });
      return;
    }

    res.status(400).json({ ok: false, error: 'Action inconnue' });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
};

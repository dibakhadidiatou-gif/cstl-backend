const { getSupabase } = require('../../lib/supabase');
const { applyCors, checkAppSecret, verifyAdminToken } = require('../../lib/auth');

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== 'POST') { res.status(405).json({ ok: false, error: 'Methode non autorisee' }); return; }
  if (!checkAppSecret(req)) { res.status(401).json({ ok: false, error: 'Secret application invalide' }); return; }

  const session = verifyAdminToken(req);
  if (!session) { res.status(401).json({ ok: false, error: 'Session administrateur requise ou expiree.' }); return; }

  try {
    const { id } = req.body || {};
    if (!id) { res.status(400).json({ ok: false, error: 'Identifiant de fiche manquant' }); return; }

    const supabase = getSupabase();
    const { data: current, error: readErr } = await supabase.from('instruction_state').select('fiches').eq('id', 'main').maybeSingle();
    if (readErr) throw readErr;

    const fiches = (current && current.fiches) || [];
    const fiche = fiches.find((f) => f.id === id);
    if (!fiche) { res.status(404).json({ ok: false, error: 'Fiche introuvable' }); return; }
    if (fiche.valide) { res.status(200).json({ ok: true, fiches }); return; } // deja validee, rien a faire

    fiche.valide = true;
    fiche.valideLe = new Date().toISOString().slice(0, 10);

    const { error: writeErr } = await supabase
      .from('instruction_state')
      .upsert({ id: 'main', fiches, updated_at: new Date().toISOString() });
    if (writeErr) throw writeErr;

    res.status(200).json({ ok: true, fiches });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
};

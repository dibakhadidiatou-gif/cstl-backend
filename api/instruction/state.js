const { getSupabase } = require('../../lib/supabase');
const { applyCors, checkAppSecret } = require('../../lib/auth');

// Une fiche validee ne peut plus jamais etre modifiee ni supprimee, meme si
// le client envoie une version modifiee ou l'omet — c'est desormais une
// regle appliquee par le serveur, pas seulement par le navigateur (qui
// pouvait etre contourne en modifiant les donnees locales).
function reconcileFiches(incoming, stored) {
  const lockedMap = new Map();
  (stored || []).forEach((f) => { if (f && f.valide) lockedMap.set(f.id, f); });

  const result = (incoming || []).map((f) => (lockedMap.has(f.id) ? lockedMap.get(f.id) : f));

  const resultIds = new Set(result.map((f) => f.id));
  lockedMap.forEach((f, id) => { if (!resultIds.has(id)) result.push(f); });

  return result;
}

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (!checkAppSecret(req)) { res.status(401).json({ ok: false, error: 'Secret application invalide' }); return; }

  try {
    const supabase = getSupabase();

    if (req.method === 'GET') {
      const { data, error } = await supabase.from('instruction_state').select('fiches').eq('id', 'main').maybeSingle();
      if (error) throw error;
      res.status(200).json({ ok: true, fiches: (data && data.fiches) || [] });
      return;
    }

    if (req.method === 'POST') {
      const incoming = (req.body && req.body.fiches) || [];
      const { data: current } = await supabase.from('instruction_state').select('fiches').eq('id', 'main').maybeSingle();
      const finalFiches = reconcileFiches(incoming, (current && current.fiches) || []);

      const { error } = await supabase
        .from('instruction_state')
        .upsert({ id: 'main', fiches: finalFiches, updated_at: new Date().toISOString() });
      if (error) throw error;

      res.status(200).json({ ok: true, fiches: finalFiches });
      return;
    }

    res.status(405).json({ ok: false, error: 'Methode non autorisee' });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
};

const { getSupabase } = require('../../lib/supabase');
const { applyCors, checkAppSecret } = require('../../lib/auth');

// Fusionne intelligemment au lieu de remplacer : plus aucune perte de
// donnees en cas d'ecriture concurrente par plusieurs personnes.
// - Une fiche presente cote serveur mais absente du tableau envoye par le
//   client n'est JAMAIS supprimee automatiquement (le client peut simplement
//   ne pas encore la connaitre) — sauf si son id figure explicitement dans
//   deletedIds (suppression volontaire faite par ce client).
// - Une fiche validee reste intouchable, meme via deletedIds.
function mergeFiches(incoming, stored, deletedIds) {
  const deletedSet = new Set(deletedIds || []);
  const storedMap = new Map((stored || []).map((f) => [f.id, f]));
  const result = [];
  const seen = new Set();

  storedMap.forEach((storedFiche, id) => {
    seen.add(id);
    if (storedFiche.valide) { result.push(storedFiche); return; }
    if (deletedSet.has(id)) { return; }
    const incomingFiche = (incoming || []).find((f) => f.id === id);
    result.push(incomingFiche || storedFiche);
  });

  (incoming || []).forEach((f) => {
    if (!seen.has(f.id)) { result.push(f); seen.add(f.id); }
  });

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
      const deletedIds = (req.body && req.body.deletedIds) || [];
      const { data: current } = await supabase.from('instruction_state').select('fiches').eq('id', 'main').maybeSingle();
      const finalFiches = mergeFiches(incoming, (current && current.fiches) || [], deletedIds);

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

const { getSupabase } = require('../../lib/supabase');
const { applyCors, checkAppSecret } = require('../../lib/auth');

function mergeById(stored, incoming, deletedIds) {
  const deletedSet = new Set(deletedIds || []);
  const storedMap = new Map((stored || []).map((e) => [e.id, e]));
  const result = [];
  const seen = new Set();

  storedMap.forEach((storedEntry, id) => {
    seen.add(id);
    if (deletedSet.has(id)) return;
    const incomingEntry = (incoming || []).find((e) => e.id === id);
    result.push(incomingEntry || storedEntry);
  });

  (incoming || []).forEach((e) => {
    if (!seen.has(e.id)) { result.push(e); seen.add(e.id); }
  });

  return result;
}

function mergeByKey(stored, incoming, key) {
  const storedMap = new Map((stored || []).map((e) => [e[key], e]));
  const result = [];
  const seen = new Set();

  storedMap.forEach((storedEntry, k) => {
    seen.add(k);
    const incomingEntry = (incoming || []).find((e) => e[key] === k);
    result.push(incomingEntry || storedEntry);
  });

  (incoming || []).forEach((e) => {
    if (!seen.has(e[key])) { result.push(e); seen.add(e[key]); }
  });

  return result;
}

// Fusionne rubrique par rubrique : les lignes de chaque rubrique sont
// combinees par id (union, rien n'est supprime sauf via deletedEntryIds).
// Les champs responsable/suppleants/extra restent en "dernier ecrit gagne"
// (risque residuel faible : peu probable que deux personnes modifient
// exactement le meme champ au meme moment).
function mergeMaintenance(incoming, stored, deletedEntryIds) {
  const result = {};
  const allKeys = new Set([...Object.keys(stored || {}), ...Object.keys(incoming || {})]);
  allKeys.forEach((key) => {
    const storedRub = (stored && stored[key]) || { responsable: '', suppleants: '', extra: {}, entries: [] };
    const incomingRub = (incoming && incoming[key]) || storedRub;
    const deletedForKey = (deletedEntryIds && deletedEntryIds[key]) || [];
    result[key] = {
      responsable: incomingRub.responsable,
      suppleants: incomingRub.suppleants,
      extra: incomingRub.extra,
      entries: mergeById(storedRub.entries, incomingRub.entries, deletedForKey)
    };
  });
  return result;
}

function mergeEffectifs(incoming, stored, deletedAgentIds) {
  const storedEff = stored || { agents: [], situations: [] };
  const incomingEff = incoming || storedEff;
  return {
    agents: mergeById(storedEff.agents, incomingEff.agents, deletedAgentIds),
    situations: mergeByKey(storedEff.situations, incomingEff.situations, 'date')
  };
}

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (!checkAppSecret(req)) { res.status(401).json({ ok: false, error: 'Secret application invalide' }); return; }

  try {
    const supabase = getSupabase();

    if (req.method === 'GET') {
      const { data, error } = await supabase.from('maintenance_state').select('maintenance, effectifs').eq('id', 'main').maybeSingle();
      if (error) throw error;
      res.status(200).json({
        ok: true,
        maintenance: (data && data.maintenance) || {},
        effectifs: (data && data.effectifs) || { agents: [], situations: [] }
      });
      return;
    }

    if (req.method === 'POST') {
      const incomingMaintenance = (req.body && req.body.maintenance) || {};
      const incomingEffectifs = (req.body && req.body.effectifs) || { agents: [], situations: [] };
      const deletedEntryIds = (req.body && req.body.deletedEntryIds) || {};
      const deletedAgentIds = (req.body && req.body.deletedAgentIds) || [];

      const { data: current } = await supabase.from('maintenance_state').select('maintenance, effectifs').eq('id', 'main').maybeSingle();
      const storedMaintenance = (current && current.maintenance) || {};
      const storedEffectifs = (current && current.effectifs) || { agents: [], situations: [] };

      const finalMaintenance = mergeMaintenance(incomingMaintenance, storedMaintenance, deletedEntryIds);
      const finalEffectifs = mergeEffectifs(incomingEffectifs, storedEffectifs, deletedAgentIds);

      const { error } = await supabase
        .from('maintenance_state')
        .upsert({ id: 'main', maintenance: finalMaintenance, effectifs: finalEffectifs, updated_at: new Date().toISOString() });
      if (error) throw error;

      res.status(200).json({ ok: true, maintenance: finalMaintenance, effectifs: finalEffectifs });
      return;
    }

    res.status(405).json({ ok: false, error: 'Methode non autorisee' });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
};

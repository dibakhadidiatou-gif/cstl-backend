const { getSupabase } = require('../../lib/supabase');
const { applyCors, checkAppSecret } = require('../../lib/auth');

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (!checkAppSecret(req)) { res.status(401).json({ ok: false, error: 'Secret application invalide' }); return; }

  try {
    console.log('SUPABASE_URL defini:', !!process.env.SUPABASE_URL);
    console.log('SUPABASE_SERVICE_ROLE_KEY defini:', !!process.env.SUPABASE_SERVICE_ROLE_KEY);
    const supabase = getSupabase();

    if (req.method === 'GET') {
      const { data, error } = await supabase.from('maintenance_state').select('maintenance, effectifs').eq('id', 'main').maybeSingle();
      if (error) {
        console.log('ERREUR Supabase (GET maintenance_state):', JSON.stringify(error));
        throw error;
      }
      res.status(200).json({
        ok: true,
        maintenance: (data && data.maintenance) || {},
        effectifs: (data && data.effectifs) || { agents: [], situations: [] }
      });
      return;
    }

    if (req.method === 'POST') {
      const maintenance = (req.body && req.body.maintenance) || {};
      const effectifs = (req.body && req.body.effectifs) || { agents: [], situations: [] };

      const { error } = await supabase
        .from('maintenance_state')
        .upsert({ id: 'main', maintenance, effectifs, updated_at: new Date().toISOString() });
      if (error) {
        console.log('ERREUR Supabase (POST maintenance_state):', JSON.stringify(error));
        throw error;
      }

      res.status(200).json({ ok: true });
      return;
    }

    res.status(405).json({ ok: false, error: 'Methode non autorisee' });
  } catch (err) {
    console.log('ERREUR maintenance/state:', String(err.message || err));
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
};

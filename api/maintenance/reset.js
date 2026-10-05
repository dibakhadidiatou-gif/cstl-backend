const { getSupabase } = require('../../lib/supabase');
const { applyCors, requireUser } = require('../../lib/auth');

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== 'POST') { res.status(405).json({ ok: false, error: 'Methode non autorisee' }); return; }

  try {
    const supabase = getSupabase();
    if (!(await requireUser(req, res, supabase, 'superadmin'))) return;
    const { error } = await supabase
      .from('maintenance_state')
      .upsert({ id: 'main', maintenance: {}, effectifs: { agents: [], situations: [] }, updated_at: new Date().toISOString() });
    if (error) throw error;
    res.status(200).json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
};

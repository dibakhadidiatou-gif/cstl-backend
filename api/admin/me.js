const { getSupabase } = require('../../lib/supabase');
const { applyCors, requireUser } = require('../../lib/auth');

// Renvoie le compte connecte et son role actuel (relu en base). Le client
// l'appelle au chargement pour afficher les actions permises, meme si le role
// a change depuis la connexion.
module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== 'GET') { res.status(405).json({ ok: false, error: 'Methode non autorisee' }); return; }

  try {
    const supabase = getSupabase();
    const user = await requireUser(req, res, supabase, 'technicien');
    if (!user) return;
    res.status(200).json({ ok: true, email: user.email, role: user.role });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
};

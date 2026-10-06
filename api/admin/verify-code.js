const crypto = require('crypto');
const { getSupabase } = require('../../lib/supabase');
const { applyCors, issueSessionToken, normalizeEmail } = require('../../lib/auth');

// Nombre maximal de codes essayes pour un meme code emis. Au-dela, le code
// est detruit et il faut en redemander un (empeche de tester les 900 000
// combinaisons possibles pendant les 10 minutes de validite).
const MAX_ATTEMPTS = 5;

function hashCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

function sameHash(a, b) {
  const bufA = Buffer.from(a, 'hex');
  const bufB = Buffer.from(b, 'hex');
  return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
}

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== 'POST') { res.status(405).json({ ok: false, error: 'Methode non autorisee' }); return; }

  try {
    const email = normalizeEmail(req.body && req.body.email);
    const code = String((req.body && req.body.code) || '').trim();
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

    // On consomme une tentative AVANT de comparer le code. La mise a jour
    // n'aboutit que si le compteur n'a pas bouge depuis la lecture : deux
    // requetes simultanees ne peuvent donc pas utiliser la meme tentative.
    const attempts = row.attempts || 0;
    if (attempts >= MAX_ATTEMPTS) {
      await supabase.from('admin_codes').delete().eq('email', email);
      res.status(200).json({ ok: false, error: 'Trop de tentatives. Redemande un code.' });
      return;
    }
    const { data: claimed, error: claimErr } = await supabase
      .from('admin_codes')
      .update({ attempts: attempts + 1 })
      .eq('email', email)
      .eq('attempts', attempts)
      .select('email');
    if (claimErr) throw claimErr;
    if (!claimed || claimed.length === 0) {
      res.status(200).json({ ok: false, error: 'Verification deja en cours, reessaie.' });
      return;
    }

    if (!sameHash(hashCode(code), row.code_hash)) {
      const left = MAX_ATTEMPTS - (attempts + 1);
      if (left <= 0) {
        await supabase.from('admin_codes').delete().eq('email', email);
        res.status(200).json({ ok: false, error: 'Code incorrect. Trop de tentatives, redemande un code.' });
      } else {
        res.status(200).json({ ok: false, error: `Code incorrect. ${left} tentative(s) restante(s).` });
      }
      return;
    }

    await supabase.from('admin_codes').delete().eq('email', email);

    // Le compte a pu etre retire entre l'envoi du code et sa saisie.
    const { data: user } = await supabase.from('users').select('email, role').eq('email', email).maybeSingle();
    if (!user) { res.status(200).json({ ok: false, error: 'Ce compte n\'existe plus. Contacte un administrateur.' }); return; }

    const token = issueSessionToken(email);
    res.status(200).json({ ok: true, token, email: user.email, role: user.role });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
};

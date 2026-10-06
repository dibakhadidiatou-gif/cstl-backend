const crypto = require('crypto');
const sgMail = require('@sendgrid/mail');
const { getSupabase } = require('../../lib/supabase');
const { applyCors, normalizeEmail } = require('../../lib/auth');

const CODE_TTL_MS = 10 * 60 * 1000;
// Delai minimal entre deux envois de code pour une meme adresse : evite
// l'envoi d'emails en rafale et limite le nombre de codes (donc de series
// de tentatives) qu'un attaquant peut obtenir.
const RESEND_DELAY_MS = 60 * 1000;

function hashCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== 'POST') { res.status(405).json({ ok: false, error: 'Methode non autorisee' }); return; }

  try {
    const email = normalizeEmail(req.body && req.body.email);
    const supabase = getSupabase();

    if (email) {
      const { data: allowed } = await supabase
        .from('users')
        .select('email')
        .eq('email', email)
        .maybeSingle();

      if (allowed) {
        // Un code emis il y a moins de RESEND_DELAY_MS est encore valable :
        // on n'en renvoie pas un nouveau. La reponse reste identique pour ne
        // pas reveler si l'adresse correspond a un compte.
        const { data: pending } = await supabase
          .from('admin_codes')
          .select('expires_at')
          .eq('email', email)
          .maybeSingle();
        const issuedAt = pending ? new Date(pending.expires_at).getTime() - CODE_TTL_MS : 0;
        if (Date.now() - issuedAt < RESEND_DELAY_MS) { res.status(200).json({ ok: true }); return; }

        const code = String(crypto.randomInt(100000, 999999));
        const expiresAt = new Date(Date.now() + CODE_TTL_MS).toISOString();
        const { error } = await supabase
          .from('admin_codes')
          .upsert({ email, code_hash: hashCode(code), expires_at: expiresAt, attempts: 0 });
        if (error) throw error;

        sgMail.setApiKey(process.env.SENDGRID_API_KEY);
        await sgMail.send({
          to: email,
          from: process.env.SENDGRID_FROM,
          subject: 'CSTL - Code de connexion administrateur',
          text: `Ton code de verification est : ${code}\n\nCe code est valable 10 minutes. Si tu n'es pas a l'origine de cette demande, ignore cet email.`
        });
      }
    }

    res.status(200).json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
};

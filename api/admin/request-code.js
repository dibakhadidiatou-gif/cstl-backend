const crypto = require('crypto');
const sgMail = require('@sendgrid/mail');
const { getSupabase } = require('../../lib/supabase');
const { applyCors } = require('../../lib/auth');

function hashCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== 'POST') { res.status(405).json({ ok: false, error: 'Methode non autorisee' }); return; }

  try {
    const { email } = req.body || {};
    const supabase = getSupabase();

    if (email) {
      const { data: allowed } = await supabase
        .from('admin_emails')
        .select('email')
        .eq('email', email)
        .maybeSingle();

      if (allowed) {
        const code = String(crypto.randomInt(100000, 999999));
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
        await supabase
          .from('admin_codes')
          .upsert({ email, code_hash: hashCode(code), expires_at: expiresAt });

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

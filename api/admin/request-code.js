const crypto = require('crypto');
const { Resend } = require('resend');
const { getSupabase } = require('../../lib/supabase');
const { applyCors, checkAppSecret } = require('../../lib/auth');

function hashCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== 'POST') { res.status(405).json({ ok: false, error: 'Methode non autorisee' }); return; }
  if (!checkAppSecret(req)) { res.status(401).json({ ok: false, error: 'Secret application invalide' }); return; }

  try {
    const { email } = req.body || {};
    const supabase = getSupabase();
    let debugInfo = { emailReceived: email, allowed: false, resendResult: null };

    if (email) {
      const { data: allowed } = await supabase
        .from('admin_emails')
        .select('email')
        .eq('email', email)
        .maybeSingle();

      debugInfo.allowed = !!allowed;

      if (allowed) {
        const code = String(crypto.randomInt(100000, 999999));
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
        await supabase
          .from('admin_codes')
          .upsert({ email, code_hash: hashCode(code), expires_at: expiresAt });

        const resend = new Resend(process.env.RESEND_API_KEY);
        const result = await resend.emails.send({
          from: process.env.RESEND_FROM || 'CSTL <onboarding@resend.dev>',
          to: email,
          subject: 'CSTL - Code de connexion administrateur',
          text: `Ton code de verification est : ${code}\n\nCe code est valable 10 minutes. Si tu n'es pas a l'origine de cette demande, ignore cet email.`
        });
        debugInfo.resendResult = result;
        console.log('Resultat envoi Resend:', JSON.stringify(result));
      }
    }

    console.log('Debug requestAdminCode:', JSON.stringify(debugInfo));
    res.status(200).json({ ok: true, debug: debugInfo });
  } catch (err) {
    console.log('ERREUR requestAdminCode:', String(err.message || err));
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
};

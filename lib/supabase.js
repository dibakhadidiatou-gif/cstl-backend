const { createClient } = require('@supabase/supabase-js');

// La cle service_role ne doit JAMAIS etre exposee au navigateur : elle vit
// uniquement ici, cote serveur, lue depuis les variables d'environnement
// Vercel (jamais commitee dans le code).
function getSupabase() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) {
    throw new Error('SUPABASE_URL ou SUPABASE_SERVICE_ROLE_KEY manquant dans les variables d\'environnement Vercel.');
  }
  return createClient(url, key, { auth: { persistSession: false } });
}

module.exports = { getSupabase };

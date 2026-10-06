const { getSupabase } = require('../../lib/supabase');
const { applyCors, requireUser, normalizeEmail, isValidRole } = require('../../lib/auth');

// Gestion des comptes depuis l'application, sans passer par le SQL Editor de
// Supabase.
// - GET                                      : liste des comptes (admin et +)
// - POST { action:'add', email, role }       : cree un compte
// - POST { action:'remove', email }          : supprime un compte
// - POST { action:'set_role', email, role }  : change le role d'un compte
// - POST { action:'bulk_add', users:[{ email, role }] } : creation en masse
//   (import CSV) ; renvoie les comptes crees et les lignes ignorees
// Un superadmin gere tous les comptes ; un admin ne gere que les techniciens.
// Personne ne peut modifier ou supprimer son propre compte (evite de se
// retrouver sans aucun superadmin).

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function canManage(actorRole, targetRole) {
  if (actorRole === 'superadmin') return true;
  return actorRole === 'admin' && targetRole === 'technicien';
}

async function listUsers(supabase) {
  const { data, error } = await supabase
    .from('users')
    .select('email, role, created_by, added_at')
    .order('added_at', { ascending: true });
  if (error) throw error;
  return data || [];
}

const MAX_BULK = 500;
// Nombre maximal de comptes de role admin (les superadmins ne comptent pas).
const MAX_ADMINS = 10;

async function countAdmins(supabase) {
  const { data, error } = await supabase.from('users').select('email').eq('role', 'admin');
  if (error) throw error;
  return (data || []).length;
}

function adminLimitMessage() {
  return `Limite atteinte : ${MAX_ADMINS} administrateurs maximum. Retire ou retrograde un admin d'abord.`;
}

// Cree plusieurs comptes d'un coup. Chaque ligne est verifiee avec les memes
// regles qu'un ajout unitaire ; une ligne refusee n'empeche pas les autres
// d'etre creees, et la raison du refus est renvoyee pour l'afficher.
async function bulkAdd(req, res, supabase, actor) {
  const rows = Array.isArray(req.body.users) ? req.body.users : [];
  if (!rows.length) { res.status(400).json({ ok: false, error: 'Aucun compte a importer.' }); return; }
  if (rows.length > MAX_BULK) { res.status(400).json({ ok: false, error: `Maximum ${MAX_BULK} comptes par import.` }); return; }

  const skipped = [];
  const candidates = new Map();
  rows.forEach((row) => {
    const email = normalizeEmail(row && row.email);
    const role = (row && row.role) || 'technicien';
    if (!EMAIL_RE.test(email)) skipped.push({ email, reason: 'adresse invalide' });
    else if (candidates.has(email)) skipped.push({ email, reason: 'en double dans le fichier' });
    else if (!isValidRole(role)) skipped.push({ email, reason: `role inconnu (${role})` });
    else if (!canManage(actor.role, role)) skipped.push({ email, reason: `ton role ne permet pas de creer un compte ${role}` });
    else candidates.set(email, role);
  });

  if (candidates.size) {
    const { data: existing, error } = await supabase.from('users').select('email, role').in('email', [...candidates.keys()]);
    if (error) throw error;
    (existing || []).forEach((u) => {
      candidates.delete(u.email);
      skipped.push({ email: u.email, reason: `compte deja existant (${u.role})` });
    });
  }

  // Les admins du fichier sont acceptes dans l'ordre, jusqu'a la limite.
  let admins = await countAdmins(supabase);
  [...candidates].forEach(([email, role]) => {
    if (role !== 'admin') return;
    if (admins >= MAX_ADMINS) {
      candidates.delete(email);
      skipped.push({ email, reason: `limite de ${MAX_ADMINS} administrateurs atteinte` });
    } else {
      admins += 1;
    }
  });

  const toInsert = [...candidates].map(([email, role]) => ({ email, role, created_by: actor.email }));
  if (toInsert.length) {
    // ignoreDuplicates : un compte cree entre-temps par quelqu'un d'autre
    // n'est pas ecrase.
    const { error } = await supabase.from('users').upsert(toInsert, { onConflict: 'email', ignoreDuplicates: true });
    if (error) throw error;
  }

  res.status(200).json({ ok: true, added: toInsert.map((u) => u.email), skipped, users: await listUsers(supabase) });
}

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;

  try {
    const supabase = getSupabase();
    const actor = await requireUser(req, res, supabase, 'admin');
    if (!actor) return;

    if (req.method === 'GET') {
      res.status(200).json({ ok: true, users: await listUsers(supabase) });
      return;
    }

    if (req.method !== 'POST') { res.status(405).json({ ok: false, error: 'Methode non autorisee' }); return; }

    const { action } = req.body || {};

    if (action === 'bulk_add') {
      await bulkAdd(req, res, supabase, actor);
      return;
    }

    const email = normalizeEmail(req.body && req.body.email);
    const role = req.body && req.body.role;
    if (!EMAIL_RE.test(email)) { res.status(400).json({ ok: false, error: 'Adresse email invalide.' }); return; }
    if (email === actor.email) { res.status(200).json({ ok: false, error: 'Tu ne peux pas modifier ton propre compte.' }); return; }

    const { data: target, error: readErr } = await supabase.from('users').select('email, role').eq('email', email).maybeSingle();
    if (readErr) throw readErr;

    if (action === 'add') {
      if (!isValidRole(role)) { res.status(400).json({ ok: false, error: 'Role invalide.' }); return; }
      if (!canManage(actor.role, role)) { res.status(403).json({ ok: false, error: 'Ton role ne permet pas de creer ce type de compte.' }); return; }
      if (target) { res.status(200).json({ ok: false, error: `Cette adresse a deja un compte (${target.role}).` }); return; }
      if (role === 'admin' && await countAdmins(supabase) >= MAX_ADMINS) { res.status(200).json({ ok: false, error: adminLimitMessage() }); return; }

      const { error } = await supabase.from('users').insert({ email, role, created_by: actor.email });
      if (error) throw error;
      res.status(200).json({ ok: true, users: await listUsers(supabase) });
      return;
    }

    if (action === 'remove') {
      if (!target) { res.status(404).json({ ok: false, error: 'Compte introuvable.' }); return; }
      if (!canManage(actor.role, target.role)) { res.status(403).json({ ok: false, error: 'Ton role ne permet pas de supprimer ce compte.' }); return; }

      const { error } = await supabase.from('users').delete().eq('email', email);
      if (error) throw error;
      await supabase.from('admin_codes').delete().eq('email', email);
      res.status(200).json({ ok: true, users: await listUsers(supabase) });
      return;
    }

    if (action === 'set_role') {
      if (!target) { res.status(404).json({ ok: false, error: 'Compte introuvable.' }); return; }
      if (!isValidRole(role)) { res.status(400).json({ ok: false, error: 'Role invalide.' }); return; }
      if (!canManage(actor.role, target.role) || !canManage(actor.role, role)) {
        res.status(403).json({ ok: false, error: 'Ton role ne permet pas ce changement.' });
        return;
      }
      if (role === 'admin' && target.role !== 'admin' && await countAdmins(supabase) >= MAX_ADMINS) {
        res.status(200).json({ ok: false, error: adminLimitMessage() });
        return;
      }

      const { error } = await supabase.from('users').update({ role }).eq('email', email);
      if (error) throw error;
      res.status(200).json({ ok: true, users: await listUsers(supabase) });
      return;
    }

    res.status(400).json({ ok: false, error: 'Action inconnue' });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
};

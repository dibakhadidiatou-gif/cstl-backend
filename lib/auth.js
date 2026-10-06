const jwt = require('jsonwebtoken');

// CORS permissif : les pages sont normalement servies par le meme site que
// l'API, mais peuvent aussi etre ouvertes ailleurs (fichier local...). Ce
// n'est pas une faille : chaque requete doit porter le jeton de session de
// l'utilisateur, envoye dans un en-tete (jamais par cookie).
function applyCors(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return true; // la fonction appelante doit s'arrêter ici
  }
  return false;
}

// Hierarchie des roles : chaque role peut faire tout ce que peuvent faire les
// roles de rang inferieur.
// - technicien : se connecte, consulte et modifie les fiches / la maintenance
// - admin      : + valide les fiches, importe/exporte, gere les techniciens
// - superadmin : + reinitialise les donnees, gere les admins et superadmins
const ROLE_RANK = { technicien: 1, admin: 2, superadmin: 3 };

function isValidRole(role) {
  return Object.prototype.hasOwnProperty.call(ROLE_RANK, role);
}

function hasRole(role, minRole) {
  return (ROLE_RANK[role] || 0) >= ROLE_RANK[minRole];
}

// Forme canonique d'une adresse email (espaces retires, minuscules), a
// utiliser partout ou une adresse est stockee ou comparee.
function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

// Emet un jeton de session (valable 24h), signe avec un secret uniquement
// connu du serveur (JWT_SECRET, variable d'environnement Vercel). Le client le
// renvoie ensuite dans l'en-tete Authorization: Bearer <token>.
function issueSessionToken(email) {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error('JWT_SECRET manquant dans les variables d\'environnement Vercel.');
  return jwt.sign({ email }, secret, { expiresIn: '24h' });
}

function readSessionToken(req) {
  const header = req.headers['authorization'] || '';
  const match = header.match(/^Bearer (.+)$/);
  if (!match) return null;
  const secret = process.env.JWT_SECRET;
  if (!secret) return null;
  try {
    return jwt.verify(match[1], secret);
  } catch (e) {
    return null;
  }
}

// Point d'entree unique des controles d'acces. Verifie le jeton de session,
// puis relit le role de l'utilisateur dans
// la table users : un compte retire ou retrograde perd ses droits
// immediatement, sans attendre l'expiration de son jeton.
// Retourne { email, role } si l'acces est accorde ; sinon repond deja au
// client (401/403) et retourne null — l'appelant doit alors s'arreter.
// Les 401 lies a la session portent code:'SESSION', pour que le client sache
// qu'il doit renvoyer l'utilisateur vers la page de connexion.
async function requireUser(req, res, supabase, minRole) {
  const session = readSessionToken(req);
  if (!session || !session.email) { res.status(401).json({ ok: false, code: 'SESSION', error: 'Connexion requise ou session expiree.' }); return null; }

  const email = normalizeEmail(session.email);
  const { data: user, error } = await supabase.from('users').select('email, role').eq('email', email).maybeSingle();
  if (error) throw error;
  if (!user) { res.status(401).json({ ok: false, code: 'SESSION', error: 'Ce compte n\'existe plus. Contacte un administrateur.' }); return null; }

  if (!hasRole(user.role, minRole)) { res.status(403).json({ ok: false, error: 'Action non autorisee pour ton role.' }); return null; }
  return user;
}

module.exports = {
  applyCors, normalizeEmail,
  ROLE_RANK, isValidRole, hasRole,
  issueSessionToken, requireUser
};

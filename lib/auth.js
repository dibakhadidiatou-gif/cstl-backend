const jwt = require('jsonwebtoken');

// CORS permissif : les fichiers HTML clients peuvent être ouverts depuis
// des origines variées (fichier local, aperçu Claude, etc.), donc on ne
// filtre pas par origine ici. La vraie protection vient du secret
// d'application (APP_SECRET) et du jeton de session de chaque utilisateur.
function applyCors(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-App-Secret');
  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return true; // la fonction appelante doit s'arrêter ici
  }
  return false;
}

// Verifie le secret d'application partage, envoye par le client dans l'en-tete
// X-App-Secret. Un premier filtre contre un usage par un tiers qui ne connait
// pas ce secret — pas une authentification individuelle.
function checkAppSecret(req) {
  const expected = process.env.APP_SECRET;
  if (!expected) return true; // si non configure, ne bloque pas (mode ouvert)
  const provided = req.headers['x-app-secret'];
  return provided === expected;
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

// Point d'entree unique des controles d'acces. Verifie le secret
// d'application, le jeton de session, puis relit le role de l'utilisateur dans
// la table users : un compte retire ou retrograde perd ses droits
// immediatement, sans attendre l'expiration de son jeton.
// Retourne { email, role } si l'acces est accorde ; sinon repond deja au
// client (401/403) et retourne null — l'appelant doit alors s'arreter.
// Les 401 lies a la session portent code:'SESSION', pour que le client sache
// qu'il doit reconnecter l'utilisateur (et non corriger le secret d'application).
async function requireUser(req, res, supabase, minRole) {
  if (!checkAppSecret(req)) { res.status(401).json({ ok: false, error: 'Secret application invalide' }); return null; }

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
  applyCors, checkAppSecret, normalizeEmail,
  ROLE_RANK, isValidRole, hasRole,
  issueSessionToken, requireUser
};

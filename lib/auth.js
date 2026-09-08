const jwt = require('jsonwebtoken');

// CORS permissif : les fichiers HTML clients peuvent être ouverts depuis
// des origines variées (fichier local, aperçu Claude, etc.), donc on ne
// filtre pas par origine ici. La vraie protection vient du secret
// d'application (APP_SECRET) et, pour les actions sensibles, du jeton de
// session administrateur.
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
// X-App-Secret. Protege les lectures/ecritures normales contre un usage par
// un tiers qui ne connait pas ce secret — un premier filtre, pas une
// authentification individuelle.
function checkAppSecret(req) {
  const expected = process.env.APP_SECRET;
  if (!expected) return true; // si non configure, ne bloque pas (mode ouvert)
  const provided = req.headers['x-app-secret'];
  return provided === expected;
}

// Emet un jeton de session administrateur (valable 12h), signe avec un
// secret uniquement connu du serveur (JWT_SECRET, variable d'environnement
// Vercel). Le client le renvoie ensuite dans l'en-tete Authorization pour
// les actions reservees a l'administrateur (valider une fiche, reinitialiser,
// modifier les reglages...).
function issueAdminToken(email) {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error('JWT_SECRET manquant dans les variables d\'environnement Vercel.');
  return jwt.sign({ email, role: 'admin' }, secret, { expiresIn: '12h' });
}

// Verifie le jeton envoye dans l'en-tete Authorization: Bearer <token>.
// Retourne les infos du jeton si valide, sinon null.
function verifyAdminToken(req) {
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

module.exports = { applyCors, checkAppSecret, issueAdminToken, verifyAdminToken };

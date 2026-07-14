// Relais Zimbra pour bilan-passage + repartition_stocks.html — Olivier Baroukh / Optical Center
// Ce Worker retransmet les appels SOAP et l'upload de pièce jointe vers Zimbra
// à côté serveur, pour contourner le blocage CORS du navigateur.
// Il persiste aussi une copie structurée de chaque bilan dans D1 (routes /store-bilan, /bilans)
// pour alimenter l'analyse centralisée, indépendante du localStorage de chaque animateur.

const ALLOWED_ORIGIN = 'https://olibaroukh.github.io';
const ZIMBRA_SOAP_URL = 'https://zimbra.oc-pratique.com/service/soap';
const ZIMBRA_UPLOAD_URL = 'https://zimbra.oc-pratique.com/service/upload?fmt=raw';

// Token secret pour sécuriser la route /notify
// À changer si compromis — doit correspondre à NOTIFY_SECRET dans index.html
const NOTIFY_SECRET = 'OC-bilan-notify-2026';

// Token secret pour sécuriser les routes de persistance D1 (/store-bilan, /bilans)
// À changer si compromis — doit correspondre à STORE_SECRET dans index.html / dashboard
const STORE_SECRET = 'OC-bilan-store-2026';

// Clé de signature interne des sessions animateur (HMAC), jamais exposée côté client
const AR_SESSION_SECRET = 'OC-bilan-arsession-2026-signing-key';
const AR_SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12h
const MAGASINS_CSV_URL = 'https://raw.githubusercontent.com/olibaroukh/bilan-passage/main/magasins.csv';

let _magasinsCache = null;
let _magasinsCacheAt = 0;

async function getMagasinsServerSide() {
  const now = Date.now();
  if (_magasinsCache && (now - _magasinsCacheAt) < 10 * 60 * 1000) return _magasinsCache;
  const resp = await fetch(MAGASINS_CSV_URL + '?v=' + now);
  const text = await resp.text();
  const lines = text.split(/\r?\n/).filter(Boolean);
  const header = lines[0].split(';').map(h => h.trim());
  const idxAnimateur = header.indexOf('animateur');
  const idxCode = header.indexOf('code');
  const rows = lines.slice(1).map(line => {
    const cols = line.split(';');
    return { code: (cols[idxCode] || '').trim(), animateur: (cols[idxAnimateur] || '').trim() };
  }).filter(r => r.code);
  _magasinsCache = rows;
  _magasinsCacheAt = now;
  return rows;
}

function normalizeName(s) {
  return (s || '')
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '.')
    .replace(/^\.+|\.+$/g, '');
}

async function hmacSign(payloadStr) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(AR_SESSION_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(payloadStr));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function createArSession(ar) {
  const payload = JSON.stringify({ ar, exp: Date.now() + AR_SESSION_TTL_MS });
  const b64 = btoa(unescape(encodeURIComponent(payload)));
  const sig = await hmacSign(b64);
  return b64 + '.' + sig;
}

async function verifyArSession(token) {
  if (!token || !token.includes('.')) return null;
  const [b64, sig] = token.split('.');
  const expectedSig = await hmacSign(b64);
  if (sig !== expectedSig) return null;
  let payload;
  try { payload = JSON.parse(decodeURIComponent(escape(atob(b64)))); } catch(e) { return null; }
  if (!payload || !payload.ar || !payload.exp || payload.exp < Date.now()) return null;
  return payload.ar;
}

function jsonError(msg, status, corsHeaders) {
  return new Response(JSON.stringify({ error: msg }), { status, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
}

function resumeBilan(b) {
  const actions = (b.actions || []).map(a => `- [${a.status || 'en cours'}] ${a.label || a.text || JSON.stringify(a)}`).join('\n') || 'Aucune action notée';
  return [
    `Date: ${b.date}${b.passage ? ' (passage n°' + b.passage + ')' : ''}`,
    `Magasin: ${b.magasin?.libelle || b.magasin_libelle || '?'} (${b.magasin?.code || b.magasin_code || '?'})`,
    `Animateur: ${b.ar || '?'}`,
    b.humeur !== undefined && b.humeur !== null ? `Humeur/ambiance (0-10): ${b.humeur}` : '',
    b.renta ? `Rentabilité: ${b.renta}%` : '',
    b.ca_mensuel ? `CA mensuel: ${b.ca_mensuel}` : '',
    b.forts ? `Points forts: ${b.forts}` : '',
    b.diff ? `Difficultés: ${b.diff}` : '',
    `Actions:\n${actions}`,
    b.manager_obs ? `Observations manager: ${b.manager_obs}` : '',
    b.remarque_libre ? `Remarque libre: ${b.remarque_libre}` : '',
  ].filter(Boolean).join('\n');
}

const OLIVIER_EMAIL = 'olivier.baroukh@optical-center.com';
const VANESSA_EMAIL = 'vanessa.baroukh@optical-center.com';

async function purgeWeeklySources(env) {
  // Purge des données brutes hebdomadaires (observations, futur pour_etre_dans_le_vert).
  // La table `bilans` (Bilan de Passage) n'est JAMAIS purgée — elle alimente l'historique
  // long de l'onglet Analyse et le futur bilan mensuel.
  try { await env.DB.prepare('DELETE FROM observations').run(); } catch(e) { console.error('Purge observations échouée:', e); }
}

async function generateObsComHebdo(obsList, env) {
  if (!Array.isArray(obsList) || !obsList.length) throw new Error('Aucune observation à traiter');
  if (!env.ANTHROPIC_API_KEY) throw new Error('Clé API Anthropic non configurée sur le Worker');

  const lines = obsList.map(o => `[${o.dl}][${o.m}][${o.th}][${o.t === 'p' ? '+' : '-'}] ${o.tx}`).join('\n');

  const systemPrompt = `Tu aides à préparer la communication hebdomadaire pour 4 magasins Optical Center (Montgeron, Vitry, Quincy, Fresnes) à partir d'observations terrain.

RÈGLES DE STYLE (à respecter strictement) :
- Ton motivant, jamais alarmiste.
- Ne JAMAIS pointer un magasin par son nom sur un point négatif — rester général plutôt que de nommer un magasin en difficulté.
- Convention interne : pour Montgeron, utilise le prénom "Eitan" (son manager) à la place du nom du magasin. Pour Vitry, utilise "Dan". Quincy et Fresnes peuvent être cités normalement.
- Français.

FORMATS ATTENDUS (réponds uniquement en JSON valide, sans texte avant/après, sans balises markdown) :
{
  "slack1": {"titre": "emoji + titre court", "contenu": "2-4 phrases", "conclusion": "1 phrase très courte et percutante"},
  "slack2": {"titre": "emoji + titre court (angle différent de slack1)", "contenu": "2-4 phrases", "conclusion": "1 phrase très courte et percutante"},
  "slack3": {"titre": "emoji + titre court (angle différent de slack1 et slack2)", "contenu": "2-4 phrases", "conclusion": "1 phrase très courte et percutante"},
  "message_general": "message autonome avec emojis, indépendant des 3 Slack (pas de redite), 4-8 phrases, ton motivant",
  "elements_mail": "liste des éléments terrain à intégrer dans le mail (PAS un mail complet rédigé — juste les points/faits marquants de la semaine, en quelques lignes, que l'auteur complètera avec le ton général, les chiffres et infos supplémentaires)"
}`;

  const userPrompt = `Voici les observations terrain de la semaine :\n\n${lines}`;

  const claudeResp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: 'claude-sonnet-5', max_tokens: 1800, system: systemPrompt, messages: [{ role: 'user', content: userPrompt }] }),
  });
  const claudeData = await claudeResp.json();
  if (!claudeResp.ok) throw new Error('Erreur API Claude : ' + JSON.stringify(claudeData));

  const rawText = (claudeData.content || []).filter(c => c.type === 'text').map(c => c.text).join('\n');
  try {
    return JSON.parse(stripJsonFences(rawText));
  } catch (e) {
    throw new Error('Réponse IA non-JSON, impossible à parser : ' + rawText.slice(0, 300));
  }
}

function formatObsEmail(fields) {
  return [
    `--- SLACK 1 ---`, fields.slack1, ``,
    `--- SLACK 2 ---`, fields.slack2, ``,
    `--- SLACK 3 ---`, fields.slack3, ``,
    `--- MESSAGE GÉNÉRAL ---`, fields.messageGeneral, ``,
    `--- ÉLÉMENTS POUR LE MAIL ---`, fields.elementsMail,
    fields.infosSupplementaires ? `\n--- INFOS SUPPLÉMENTAIRES ---\n${fields.infosSupplementaires}` : '',
  ].filter(x => x !== undefined && x !== '').join('\n');
}

function mostRecentWeekRange() {
  // Couvre le lundi -> vendredi le plus récent, peu importe le jour d'exécution (samedi ou dimanche)
  const now = new Date();
  const day = now.getUTCDay(); // 0=dim, 1=lun, ..., 5=ven, 6=sam
  const diffToFriday = ((day - 5) + 7) % 7 || 7; // nombre de jours depuis le dernier vendredi (jamais 0 ici : on tourne sam/dim)
  const friday = new Date(now); friday.setUTCDate(now.getUTCDate() - diffToFriday);
  const monday = new Date(friday); monday.setUTCDate(friday.getUTCDate() - 4);
  const fmt = d => d.toISOString().slice(0, 10);
  return { from: fmt(monday), to: fmt(friday) };
}

async function getWeekData(env) {
  const { from, to } = mostRecentWeekRange();
  const { results } = await env.DB.prepare(
    'SELECT * FROM bilans WHERE date >= ? AND date <= ? ORDER BY ar, date'
  ).bind(from, to).all();
  const bilans = results.map(r => { try { return JSON.parse(r.data_json); } catch(e) { return r; } });

  const stores = await getMagasinsServerSide();
  const allARs = [...new Set(stores.map(s => s.animateur).filter(Boolean))].sort();

  const byAR = {};
  allARs.forEach(a => byAR[a] = []);
  bilans.forEach(b => {
    const ar = b.ar || 'Non renseigné';
    if (!byAR[ar]) byAR[ar] = [];
    byAR[ar].push(b);
  });

  return { from, to, bilans, allARs, byAR };
}

async function zimbraSendMail(env, { to, subject, bodyText }) {
  const authResp = await fetch(ZIMBRA_SOAP_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      Header: { context: { _jsns: 'urn:zimbra', format: { _content: 'js', type: 'js' } } },
      Body: {
        AuthRequest: {
          _jsns: 'urn:zimbraAccount',
          account: { by: 'name', _content: env.ZIMBRA_CRON_USER },
          password: { _content: env.ZIMBRA_CRON_PASS }
        }
      }
    })
  });
  const authData = await authResp.json();
  const token = authData?.Body?.AuthResponse?.authToken?.[0]?._content;
  if (!token) throw new Error('Authentification Zimbra (compte cron) échouée');

  const sendResp = await fetch(ZIMBRA_SOAP_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Cookie': `ZM_AUTH_TOKEN=${token}` },
    body: JSON.stringify({
      Header: { context: { _jsns: 'urn:zimbra', format: { _content: 'js', type: 'js' }, authToken: [{ _content: token }] } },
      Body: {
        SendMsgRequest: {
          _jsns: 'urn:zimbraMail',
          m: { su: { _content: subject }, e: [{ t: 't', a: to }], mp: { ct: 'text/plain', content: { _content: bodyText } } }
        }
      }
    })
  });
  if (!sendResp.ok) throw new Error('Envoi email échoué (' + sendResp.status + ')');
}

async function generateWeeklyReport(env) {
  const { from, to, bilans, byAR } = await getWeekData(env);

  const sections = Object.entries(byAR).map(([ar, list]) => {
    if (!list.length) return `=== ${ar} ===\nAucun bilan de passage enregistré cette semaine.`;
    return `=== ${ar} (${list.length} bilan(s)) ===\n` + list.map(resumeBilan).join('\n\n---\n\n');
  }).join('\n\n\n');

  const systemPrompt = `Tu prépares le bilan hebdomadaire du réseau Optical Center pour le directeur réseau. Pour CHAQUE animateur listé (même ceux sans bilan cette semaine), produis une section avec : (1) les sujets les plus souvent abordés ou contrôlés durant les passages de la semaine, (2) les résultats relevés (chiffres, tendances, points notables). Si un animateur n'a aucun bilan, dis-le simplement en une ligne. Reste factuel, base-toi uniquement sur les données fournies, sois concis et actionnable. Structure par animateur avec un titre clair.`;

  let analysis = '(Aucune donnée cette semaine.)';
  let debugInfo = { from, to, totalBilans: bilans.length, byAR: Object.fromEntries(Object.entries(byAR).map(([k,v]) => [k, v.length])) };

  if (bilans.length && env.ANTHROPIC_API_KEY) {
    const claudeResp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-5', max_tokens: 2000, system: systemPrompt, messages: [{ role: 'user', content: sections }] }),
    });
    const claudeData = await claudeResp.json();
    if (claudeResp.ok) {
      analysis = (claudeData.content || []).filter(c => c.type === 'text').map(c => c.text).join('\n');
    } else {
      analysis = '(Erreur génération synthèse IA : ' + JSON.stringify(claudeData) + ')';
    }
  }

  const subject = `Bilan hebdomadaire réseau — semaine du ${from.split('-').reverse().join('/')} au ${to.split('-').reverse().join('/')}`;
  return { subject, analysis, debugInfo };
}

async function sendWeeklyReport(env) {
  const { subject, analysis } = await generateWeeklyReport(env);
  await zimbraSendMail(env, { to: OLIVIER_EMAIL, subject, bodyText: analysis });
}

function stripJsonFences(text) {
  return text.replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/i, '').trim();
}

async function generateComHebdo(env) {
  const { from, to, bilans, byAR } = await getWeekData(env);

  const sections = Object.entries(byAR)
    .filter(([, list]) => list.length)
    .map(([ar, list]) => `=== ${ar} (${list.length} bilan(s)) ===\n` + list.map(resumeBilan).join('\n\n---\n\n'))
    .join('\n\n\n');

  const contentSource = sections || '(Aucun bilan de passage enregistré cette semaine sur le réseau.)';

  const systemPrompt = `Tu es l'assistant d'Olivier, Animateur Réseau chez Optical Center, pour rédiger sa communication hebdomadaire interne à partir des observations terrain (bilans de passage) de la semaine.

RÈGLES DE STYLE (à respecter strictement) :
- Ton motivant, jamais alarmiste.
- Ne JAMAIS pointer un magasin par son nom sur un point négatif — rester général ou parler de tendances réseau plutôt que de nommer un magasin en difficulté.
- Convention interne : quand tu évoques le magasin de Montgeron, utilise le prénom "Eitan" (son manager) à la place du nom du magasin. Quand tu évoques Vitry, utilise "Dan". Pour tous les autres magasins, tu peux les citer par leur nom si c'est positif.
- Tu écris en français.

FORMATS ATTENDUS (réponds uniquement en JSON valide, sans texte avant/après, sans balises markdown) :
{
  "slack1": {"titre": "emoji + titre court", "contenu": "2-4 phrases", "conclusion": "1 phrase percutante"},
  "slack2": {"titre": "emoji + titre court (angle différent de slack1)", "contenu": "2-4 phrases", "conclusion": "1 phrase percutante"},
  "slack3": {"titre": "emoji + titre court (angle différent de slack1 et slack2)", "contenu": "2-4 phrases", "conclusion": "1 phrase percutante"},
  "message_general": "message autonome avec emojis, 4-8 phrases, ton motivant, à poster tel quel",
  "email_objet": "objet de l'email, sans emoji",
  "email_corps": "email narratif plus long (8-15 phrases), SANS AUCUN EMOJI (contrainte technique Zimbra), ton professionnel et motivant, qui raconte la semaine du réseau"
}

Les 3 messages Slack doivent couvrir des angles différents (ex: un fait marquant de la semaine, un point de vigilance collectif sans nommer de magasin, un encouragement/objectif pour la semaine à venir) — évite les répétitions entre eux.`;

  const userPrompt = `Voici les observations terrain (bilans de passage) de la semaine du ${from} au ${to}, par animateur :\n\n${contentSource}`;

  if (!env.ANTHROPIC_API_KEY) {
    throw new Error('Clé API Anthropic non configurée sur le Worker');
  }

  const claudeResp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: 'claude-sonnet-5', max_tokens: 2500, system: systemPrompt, messages: [{ role: 'user', content: userPrompt }] }),
  });
  const claudeData = await claudeResp.json();
  if (!claudeResp.ok) throw new Error('Erreur API Claude : ' + JSON.stringify(claudeData));

  const rawText = (claudeData.content || []).filter(c => c.type === 'text').map(c => c.text).join('\n');
  let blocks;
  try {
    blocks = JSON.parse(stripJsonFences(rawText));
  } catch (e) {
    throw new Error('Réponse IA non-JSON, impossible à parser : ' + rawText.slice(0, 300));
  }

  return { from, to, blocks };
}

function formatComHebdoAsEmail(blocks) {
  return [
    `--- SLACK 1 ---`,
    `${blocks.slack1?.titre}\n${blocks.slack1?.contenu}\n${blocks.slack1?.conclusion}`,
    ``,
    `--- SLACK 2 ---`,
    `${blocks.slack2?.titre}\n${blocks.slack2?.contenu}\n${blocks.slack2?.conclusion}`,
    ``,
    `--- SLACK 3 ---`,
    `${blocks.slack3?.titre}\n${blocks.slack3?.contenu}\n${blocks.slack3?.conclusion}`,
    ``,
    `--- MESSAGE GÉNÉRAL ---`,
    blocks.message_general,
    ``,
    `--- EMAIL (objet: ${blocks.email_objet}) ---`,
    blocks.email_corps,
  ].join('\n');
}

async function sendComHebdo(env) {
  const { from, to, blocks } = await generateComHebdo(env);
  const subject = `Com hebdo réseau (brouillon) — semaine du ${from.split('-').reverse().join('/')} au ${to.split('-').reverse().join('/')}`;
  await zimbraSendMail(env, { to: OLIVIER_EMAIL, subject, bodyText: formatComHebdoAsEmail(blocks) });
}

export default {
  async fetch(request, env) {
    const corsHeaders = {
      'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
      'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Zimbra-Auth-Token, X-Notify-Token, X-Store-Token, X-AR-Session',
      'Access-Control-Max-Age': '86400',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const url = new URL(request.url);

    if (request.method !== 'POST' && !(request.method === 'GET' && (url.pathname === '/bilans' || url.pathname === '/test-weekly-report' || url.pathname === '/com-hebdo' || url.pathname === '/test-com-hebdo'))) {
      return new Response('Méthode non autorisée', { status: 405, headers: corsHeaders });
    }

    try {
      if (url.pathname === '/upload') {
        const token = request.headers.get('X-Zimbra-Auth-Token');
        if (!token) {
          return new Response('Jeton manquant', { status: 400, headers: corsHeaders });
        }
        const contentType = request.headers.get('Content-Type') || '';
        const bodyBuffer = await request.arrayBuffer();
        const uploadRes = await fetch(ZIMBRA_UPLOAD_URL, {
          method: 'POST',
          headers: { 'Content-Type': contentType, 'Cookie': `ZM_AUTH_TOKEN=${token}` },
          body: bodyBuffer,
        });
        const text = await uploadRes.text();
        return new Response(text, {
          status: uploadRes.status,
          headers: { 'Content-Type': 'text/plain', ...corsHeaders },
        });
      }

      if (url.pathname === '/notify') {
        // Vérification du token secret
        const notifyToken = request.headers.get('X-Notify-Token');
        if (notifyToken !== NOTIFY_SECRET) {
          return new Response('Non autorisé', { status: 401, headers: corsHeaders });
        }
        const { to, subject, body, zimbraUser, zimbraPass } = await request.json();
        if (!to || !subject || !body || !zimbraUser || !zimbraPass) {
          return new Response('Paramètres manquants', { status: 400, headers: corsHeaders });
        }
        // Authentification Zimbra
        const authResp = await fetch(ZIMBRA_SOAP_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            Header: { context: { _jsns: 'urn:zimbra', format: { _content: 'js', type: 'js' } } },
            Body: {
              AuthRequest: {
                _jsns: 'urn:zimbraAccount',
                account: { by: 'name', _content: zimbraUser },
                password: { _content: zimbraPass }
              }
            }
          })
        });
        const authData = await authResp.json();
        const token = authData?.Body?.AuthResponse?.authToken?.[0]?._content;
        if (!token) {
          return new Response('Auth Zimbra échouée', { status: 401, headers: corsHeaders });
        }
        // Envoi du mail de notification
        const sendResp = await fetch(ZIMBRA_SOAP_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Cookie': `ZM_AUTH_TOKEN=${token}` },
          body: JSON.stringify({
            Header: {
              context: {
                _jsns: 'urn:zimbra',
                format: { _content: 'js', type: 'js' },
                authToken: [{ _content: token }]
              }
            },
            Body: {
              SendMsgRequest: {
                _jsns: 'urn:zimbraMail',
                m: {
                  su: { _content: subject },
                  e: [{ t: 't', a: to }],
                  mp: { ct: 'text/plain', content: { _content: body } }
                }
              }
            }
          })
        });
        const sendText = await sendResp.text();
        return new Response(sendText, {
          status: sendResp.status,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      if (url.pathname === '/ar-login') {
        const storeToken = request.headers.get('X-Store-Token');
        if (storeToken !== STORE_SECRET) return jsonError('Non autorisé', 401, corsHeaders);

        const { zimbraUser, zimbraPass } = await request.json();
        if (!zimbraUser || !zimbraPass) return jsonError('Identifiant et mot de passe requis', 400, corsHeaders);

        // Authentification réelle auprès de Zimbra (preuve de possession du compte)
        const authResp = await fetch(ZIMBRA_SOAP_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            Header: { context: { _jsns: 'urn:zimbra', format: { _content: 'js', type: 'js' } } },
            Body: {
              AuthRequest: {
                _jsns: 'urn:zimbraAccount',
                account: { by: 'name', _content: zimbraUser },
                password: { _content: zimbraPass }
              }
            }
          })
        });
        const authData = await authResp.json();
        const zimbraToken = authData?.Body?.AuthResponse?.authToken?.[0]?._content;
        if (!zimbraToken) return jsonError('Identifiants Zimbra invalides', 401, corsHeaders);

        // Résolution serveur de l'identité AR à partir du référentiel magasins.csv
        // (jamais depuis des données envoyées par le téléphone)
        const localPart = zimbraUser.split('@')[0];
        const normalizedLogin = normalizeName(localPart);
        let ar = null;
        if (normalizedLogin.includes('baroukh')) {
          ar = 'ALL';
        } else {
          const stores = await getMagasinsServerSide();
          const uniqueARs = [...new Set(stores.map(s => s.animateur).filter(Boolean))];
          ar = uniqueARs.find(a => normalizeName(a) === normalizedLogin) || null;
        }
        if (!ar) {
          return jsonError("Identifiants valides mais aucun animateur ne correspond à '" + zimbraUser + "' dans le référentiel magasins. Vérifie l'orthographe du login vs le nom animateur dans magasins.csv.", 403, corsHeaders);
        }

        const sessionToken = await createArSession(ar);
        return new Response(JSON.stringify({ ok: true, sessionToken, ar, expiresInMs: AR_SESSION_TTL_MS }), {
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }

      if (url.pathname === '/store-bilan') {
        const storeToken = request.headers.get('X-Store-Token');
        if (storeToken !== STORE_SECRET) {
          return new Response('Non autorisé', { status: 401, headers: corsHeaders });
        }
        if (!env.DB) {
          return new Response('Base D1 non liée au Worker', { status: 500, headers: corsHeaders });
        }
        const data = await request.json();
        const magasinCode = data?.magasin?.code || null;
        const magasinLibelle = data?.magasin?.libelle || null;
        if (!magasinCode || !data?.date) {
          return new Response('Champs requis manquants (magasin.code, date)', { status: 400, headers: corsHeaders });
        }
        await env.DB.prepare(
          `INSERT INTO bilans (magasin_code, magasin_libelle, ar, date, passage, humeur, ca_mensuel, ca_annuel, renta, data_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(
          magasinCode,
          magasinLibelle,
          data.ar || null,
          data.date,
          data.passage || null,
          data.humeur !== undefined && data.humeur !== '' ? parseInt(data.humeur) : null,
          data.ca_mensuel || null,
          data.ca_annuel || null,
          data.renta || null,
          JSON.stringify(data)
        ).run();
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }

      if (url.pathname === '/bilans') {
        const storeToken = request.headers.get('X-Store-Token');
        if (storeToken !== STORE_SECRET) return jsonError('Non autorisé', 401, corsHeaders);
        if (!env.DB) return jsonError('Base D1 non liée au Worker', 500, corsHeaders);

        const sessionAr = await verifyArSession(request.headers.get('X-AR-Session'));
        if (!sessionAr) return jsonError('Session animateur invalide ou expirée, reconnecte-toi.', 401, corsHeaders);

        let allowedCodes = null;
        if (sessionAr !== 'ALL') {
          const stores = await getMagasinsServerSide();
          allowedCodes = stores.filter(s => s.animateur === sessionAr).map(s => s.code);
        }

        const magasinCode = url.searchParams.get('magasin_code');
        if (magasinCode && allowedCodes && !allowedCodes.includes(magasinCode)) {
          return jsonError('Accès non autorisé à ce magasin', 403, corsHeaders);
        }
        const from = url.searchParams.get('from');
        const to = url.searchParams.get('to');
        const limit = Math.min(parseInt(url.searchParams.get('limit') || '200'), 1000);

        let query = 'SELECT id, magasin_code, magasin_libelle, ar, date, passage, humeur, ca_mensuel, ca_annuel, renta, data_json, created_at FROM bilans WHERE 1=1';
        const binds = [];
        if (magasinCode) {
          query += ' AND magasin_code = ?'; binds.push(magasinCode);
        } else if (allowedCodes) {
          if (!allowedCodes.length) return new Response(JSON.stringify({ ok: true, results: [] }), { status: 200, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
          query += ' AND magasin_code IN (' + allowedCodes.map(() => '?').join(',') + ')';
          binds.push(...allowedCodes);
        }
        if (from) { query += ' AND date >= ?'; binds.push(from); }
        if (to) { query += ' AND date <= ?'; binds.push(to); }
        query += ' ORDER BY date DESC LIMIT ?';
        binds.push(limit);

        const { results } = await env.DB.prepare(query).bind(...binds).all();
        return new Response(JSON.stringify({ ok: true, results }), {
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }

      if (url.pathname === '/analyze') {
        const storeToken = request.headers.get('X-Store-Token');
        if (storeToken !== STORE_SECRET) {
          return new Response(JSON.stringify({ error: 'Non autorisé' }), { status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }
        const sessionAr = await verifyArSession(request.headers.get('X-AR-Session'));
        if (!sessionAr) return jsonError('Session animateur invalide ou expirée, reconnecte-toi.', 401, corsHeaders);
        if (!env.ANTHROPIC_API_KEY) {
          return new Response(JSON.stringify({ error: 'Clé API Anthropic non configurée sur le Worker (secret ANTHROPIC_API_KEY manquant ou non déployé)' }), { status: 500, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }
        const { mode, bilans } = await request.json();
        if (!Array.isArray(bilans) || !bilans.length) {
          return new Response(JSON.stringify({ error: 'Aucune donnée à analyser' }), { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }

        let systemPrompt, userContent;
        if (mode === 'group') {
          systemPrompt = `Tu es un assistant qui aide un animateur réseau (AR) d'Optical Center à préparer sa tournée terrain. On te donne l'historique récent de plusieurs magasins. Pour chaque magasin, produis une synthèse courte et actionnable : tendance générale, actions non résolues qui traînent, et 1 à 2 points de vigilance prioritaires. Reste factuel, base-toi uniquement sur les données fournies, sois concis (pas de blabla). Structure ta réponse par magasin avec un titre clair.`;
          userContent = bilans.map((storeBilans, i) =>
            `=== Magasin ${i + 1} ===\n` + storeBilans.map(resumeBilan).join('\n\n---\n\n')
          ).join('\n\n\n');
        } else {
          systemPrompt = `Tu es un assistant qui aide un animateur réseau (AR) d'Optical Center à analyser l'historique d'un magasin. On te donne les bilans de passage successifs. Identifie les tendances (amélioration/dégradation), les actions récurrentes qui ne sont jamais résolues, et les points d'alerte. Reste factuel, base-toi uniquement sur les données fournies, sois concis et actionnable.`;
          userContent = bilans.map(resumeBilan).join('\n\n---\n\n');
        }

        const claudeResp = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': env.ANTHROPIC_API_KEY,
            'anthropic-version': '2023-06-01',
          },
          body: JSON.stringify({
            model: 'claude-sonnet-5',
            max_tokens: 1500,
            system: systemPrompt,
            messages: [{ role: 'user', content: userContent }],
          }),
        });
        const claudeData = await claudeResp.json();
        if (!claudeResp.ok) {
          return new Response(JSON.stringify({ error: claudeData }), {
            status: claudeResp.status,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
          });
        }
        const analysis = (claudeData.content || []).filter(c => c.type === 'text').map(c => c.text).join('\n');
        return new Response(JSON.stringify({ ok: true, analysis }), {
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }

      if (url.pathname === '/store-observation') {
        const storeToken = request.headers.get('X-Store-Token');
        if (storeToken !== STORE_SECRET) return jsonError('Non autorisé', 401, corsHeaders);
        if (!env.DB) return jsonError('Base D1 non liée au Worker', 500, corsHeaders);
        try {
          const o = await request.json();
          if (!o.m || !o.th || !o.tx || !o.t || !o.d) return jsonError('Champs requis manquants', 400, corsHeaders);
          await env.DB.prepare(
            `INSERT INTO observations (obs_id, magasin, theme, tone, texte, jour_label, date_key)
             VALUES (?, ?, ?, ?, ?, ?, ?)`
          ).bind(o.id || null, o.m, o.th, o.t, o.tx, o.dl || null, o.d).run();
          return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        } catch (e) {
          return jsonError('Erreur enregistrement : ' + String(e), 500, corsHeaders);
        }
      }

      if (url.pathname === '/obs-generate') {
        const storeToken = request.headers.get('X-Store-Token');
        if (storeToken !== STORE_SECRET) return jsonError('Non autorisé', 401, corsHeaders);
        try {
          const { obs } = await request.json();
          const blocks = await generateObsComHebdo(obs, env);
          return new Response(JSON.stringify({ ok: true, blocks }), { status: 200, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        } catch (e) {
          return jsonError('Erreur génération : ' + String(e), 500, corsHeaders);
        }
      }

      if (url.pathname === '/obs-send') {
        const storeToken = request.headers.get('X-Store-Token');
        if (storeToken !== STORE_SECRET) return jsonError('Non autorisé', 401, corsHeaders);
        try {
          const fields = await request.json();
          if (!fields.slack1 && !fields.messageGeneral) return jsonError('Contenu manquant', 400, corsHeaders);
          const bodyText = formatObsEmail(fields);
          const subject = `Com hebdo — Montgeron / Vitry / Quincy / Fresnes`;
          await zimbraSendMail(env, { to: OLIVIER_EMAIL, subject, bodyText });
          await zimbraSendMail(env, { to: VANESSA_EMAIL, subject, bodyText });
          return new Response(JSON.stringify({ ok: true, sentTo: [OLIVIER_EMAIL, VANESSA_EMAIL] }), { status: 200, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        } catch (e) {
          return jsonError('Erreur envoi : ' + String(e), 500, corsHeaders);
        }
      }

      if (url.pathname === '/com-hebdo') {
        const storeToken = request.headers.get('X-Store-Token');
        if (storeToken !== STORE_SECRET) return jsonError('Non autorisé', 401, corsHeaders);
        const sessionAr = await verifyArSession(request.headers.get('X-AR-Session'));
        if (!sessionAr) return jsonError('Session animateur invalide ou expirée, reconnecte-toi.', 401, corsHeaders);
        if (sessionAr !== 'ALL') return jsonError('Fonctionnalité réservée au profil réseau complet', 403, corsHeaders);
        if (!env.DB) return jsonError('Base D1 non liée au Worker', 500, corsHeaders);
        try {
          const { from, to, blocks } = await generateComHebdo(env);
          return new Response(JSON.stringify({ ok: true, from, to, blocks }), { status: 200, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        } catch (e) {
          return jsonError('Erreur génération com hebdo : ' + String(e), 500, corsHeaders);
        }
      }

      if (url.pathname === '/test-com-hebdo') {
        const storeToken = request.headers.get('X-Store-Token') || url.searchParams.get('token');
        if (storeToken !== STORE_SECRET) return jsonError('Non autorisé', 401, corsHeaders);
        if (!env.DB) return jsonError('Base D1 non liée au Worker', 500, corsHeaders);
        const sendEmail = url.searchParams.get('send') === '1'; // explicite : par défaut on ne fait que prévisualiser
        try {
          const { from, to, blocks } = await generateComHebdo(env);
          if (sendEmail) {
            const subject = `Com hebdo réseau (brouillon) — semaine du ${from.split('-').reverse().join('/')} au ${to.split('-').reverse().join('/')}`;
            await zimbraSendMail(env, { to: OLIVIER_EMAIL, subject, bodyText: formatComHebdoAsEmail(blocks) });
          }
          return new Response(JSON.stringify({ ok: true, emailSent: sendEmail, from, to, blocks }, null, 2), { status: 200, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        } catch (e) {
          return jsonError('Erreur génération/envoi com hebdo : ' + String(e), 500, corsHeaders);
        }
      }

      if (url.pathname === '/test-weekly-report') {
        const storeToken = request.headers.get('X-Store-Token') || url.searchParams.get('token');
        if (storeToken !== STORE_SECRET) return jsonError('Non autorisé', 401, corsHeaders);
        if (!env.DB) return jsonError('Base D1 non liée au Worker', 500, corsHeaders);
        const sendEmail = url.searchParams.get('send') !== '0'; // ?send=0 pour prévisualiser sans envoyer
        try {
          const { subject, analysis, debugInfo } = await generateWeeklyReport(env);
          if (sendEmail) await zimbraSendMail(env, { to: OLIVIER_EMAIL, subject, bodyText: analysis });
          return new Response(JSON.stringify({
            ok: true,
            emailSent: sendEmail,
            to: sendEmail ? OLIVIER_EMAIL : null,
            subject,
            analysis,
            debugInfo
          }, null, 2), { status: 200, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        } catch (e) {
          return jsonError('Erreur génération/envoi du rapport : ' + String(e), 500, corsHeaders);
        }
      }

      // par défaut : relais SOAP (AuthRequest, SendMsgRequest, ...)
      const body = await request.text();
      const zimbraResponse = await fetch(ZIMBRA_SOAP_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
      const text = await zimbraResponse.text();
      return new Response(text, {
        status: zimbraResponse.status,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: String(err) }), {
        status: 502,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });
    }
  },

  async scheduled(event, env, ctx) {
    if (event.cron === '0 7 * * 0') {
      ctx.waitUntil(sendComHebdo(env).catch(e => console.error('Erreur com hebdo:', e)));
    } else if (event.cron === '0 20 * * 0') {
      ctx.waitUntil(purgeWeeklySources(env).catch(e => console.error('Erreur purge hebdomadaire:', e)));
    } else {
      ctx.waitUntil(sendWeeklyReport(env).catch(e => console.error('Erreur rapport hebdomadaire:', e)));
    }
  }
};

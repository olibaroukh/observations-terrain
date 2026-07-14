-- Table pour l'écriture au fil de l'eau des observations terrain
-- (purgée chaque dimanche ~22h après les derniers exports de la semaine)

CREATE TABLE IF NOT EXISTS observations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  obs_id INTEGER,          -- id client (Date.now()) pour référence/dédup éventuelle
  magasin TEXT NOT NULL,
  theme TEXT NOT NULL,
  tone TEXT NOT NULL,      -- 'p' (positif) ou 'n' (à améliorer)
  texte TEXT NOT NULL,
  jour_label TEXT,         -- ex: "Lundi 13/07"
  date_key TEXT NOT NULL,  -- ex: "2026-07-13" (ISO, zero-paddé)
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_obs_date ON observations(date_key);
CREATE INDEX IF NOT EXISTS idx_obs_magasin ON observations(magasin);

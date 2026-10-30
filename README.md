# Projet 1 — Analyse des journaux d'un pare-feu

**Nom / Prénom** : BABA SADY RSIoT, ISEP Diamniadio

## Lancer le projet

```bash
pip install -r requirements.txt
python analyse.py
```

Le script lit `data/logs_reseau.csv`, nettoie les données, écrit `resultats.json`
et enregistre les figures PNG dans `figures/`.

## Contenu

- `analyse.py` : nettoyage, calcul des 5 résultats, figures
- `resultats.json` : résultats générés
- `figures/` : 7 graphiques
- `rapport.md` : observations, comportements suspects, recommandations

## Résultats

| Clé | Valeur |
|---|---|
| nb_lignes_apres_nettoyage | 5440 |
| top_port | 443 |
| taux_deny_pct | 13.57 |
| ip_scanner | 192.168.1.99 |
| ip_exfiltration | 192.168.1.11 |

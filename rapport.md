# Rapport d'analyse — journaux du pare-feu (5 au 11 octobre 2026)

**Auteur** : BABA SADY

## Résumé

Après nettoyage, le journal contient 5 440 connexions (60 doublons supprimés, 166 `bytes_sent` manquants remplacés par la médiane, casse de `protocol` corrigée). Le trafic est dominé par HTTPS (port 443, 1 900 connexions) puis HTTP, DNS et MQTT. 13,57 % des connexions sont bloquées (DENY). Le trafic est stable d'un jour à l'autre (environ 650 à 800 connexions), sauf le 8 octobre (1 137) à cause d'un scan. Deux comportements anormaux ressortent : un scan de ports depuis un PC et un envoi massif de données par une caméra IoT.

## Comportement suspect n°1 — Scan de ports depuis 192.168.1.99

- Cette IP (un **PC**) a contacté **328 ports distincts** d'une seule machine de destination. Les autres IP en contactent **8 au maximum**.
- Elle a généré **400 connexions en 15 minutes** (le 8 octobre entre 00:00 et 00:15), ce qui explique le pic du 8 octobre.
- **383 de ces 400 connexions (95,8 %) ont été bloquées**, mais 17 sont passées (ALLOW).
- Preuve : figure `figures/ports_distincts_par_ip.png`.

Interprétation : c'est le profil classique d'une reconnaissance (balayage de ports), probablement une machine compromise ou un utilisateur malveillant qui cherche des services ouverts.

## Comportement suspect n°2 — Exfiltration depuis la caméra 192.168.1.11

- Cette IP (une **caméra IoT**) a envoyé **environ 260 Mo** au total, alors que toutes les autres IP envoient moins de 0,7 Mo chacune. Elle représente environ 95 % du volume total du réseau (274,6 Mo).
- **38 transferts de 5 à 8,7 Mo chacun**, tous le **10 octobre**, vers **8.8.8.8 sur le port 8080**, tous **autorisés** par le pare-feu. Pour comparaison, la médiane des autres connexions est de 1,7 Ko.
- Preuve : figures `figures/octets_par_ip.png` et `figures/octets_par_appareil.png`.

Interprétation : une caméra n'a aucune raison d'envoyer de tels volumes vers une IP externe sur le port 8080. C'est un signe probable de fuite de données (exfiltration) ou de caméra compromise (botnet). Remarque : 8.8.8.8 est une IP DNS publique, la destination pourrait être usurpée ou servir de couverture.

## Recommandations de sécurité

1. **Isoler la caméra 192.168.1.11** immédiatement, vérifier son firmware, changer ses identifiants et analyser ses connexions du 10 octobre.
2. **Segmenter les objets IoT** dans un VLAN dédié, avec une règle « deny all » par défaut et seulement les flux nécessaires (par exemple MQTT vers le broker interne).
3. **Bloquer le trafic sortant inutile** : interdire le port 8080 sortant depuis les caméras et limiter la destination 8.8.8.8 au port 53 (DNS) seulement.
4. **Mettre en place une alerte** de volume (seuil d'octets par IP et par heure) pour détecter les envois anormaux.
5. **Limiter les scans** : règle de blocage automatique (ou alerte IDS) d'une IP source qui touche plus de N ports distincts en quelques minutes, et enquêter sur le PC 192.168.1.99 (antivirus, analyse forensique).
6. **Fermer Telnet (port 23)** : 100 connexions Telnet observées, dont 26 autorisées. Utiliser SSH à la place, et restreindre SSH/RDP aux postes d'administration.

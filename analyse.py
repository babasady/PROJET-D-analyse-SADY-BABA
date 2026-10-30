"""Projet 1 - Analyse des journaux d'un pare-feu.

Usage : python analyse.py
Produit : resultats.json + figures/*.png
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # pas de fenêtre, on enregistre seulement les PNG
import matplotlib.pyplot as plt
import pandas as pd

DATA = Path("data/logs_reseau.csv")
FIG_DIR = Path("figures")
FIG_DIR.mkdir(exist_ok=True)


def nettoyer(df: pd.DataFrame) -> pd.DataFrame:
    """Doublons exacts, protocol en MAJUSCULES, bytes_sent manquants -> médiane."""
    df = df.drop_duplicates().copy()
    df["protocol"] = df["protocol"].str.upper()
    mediane = df["bytes_sent"].median()  # calculée APRÈS suppression des doublons
    df["bytes_sent"] = df["bytes_sent"].fillna(mediane)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df.reset_index(drop=True)


def calculer_resultats(df: pd.DataFrame) -> dict:
    ports_par_ip = df.groupby("src_ip")["dst_port"].nunique()
    octets_par_ip = df.groupby("src_ip")["bytes_sent"].sum()
    return {
        "nb_lignes_apres_nettoyage": int(len(df)),
        "top_port": int(df["dst_port"].value_counts().idxmax()),
        "taux_deny_pct": round(float((df["action"] == "DENY").mean() * 100), 2),
        "ip_scanner": str(ports_par_ip.idxmax()),
        "ip_exfiltration": str(octets_par_ip.idxmax()),
    }


def sauver(nom: str):
    plt.tight_layout()
    plt.savefig(FIG_DIR / nom, dpi=120)
    plt.close()


def faire_figures(df: pd.DataFrame) -> None:
    # 1. Top 10 des ports de destination
    top = df["dst_port"].value_counts().head(10)
    plt.figure(figsize=(8, 5))
    plt.bar(top.index.astype(str), top.values, color="steelblue")
    plt.title("Top 10 des ports de destination")
    plt.xlabel("Port de destination")
    plt.ylabel("Nombre de connexions")
    sauver("top_ports.png")

    # 2. Connexions par jour
    par_jour = df.groupby(df["timestamp"].dt.date).size()
    plt.figure(figsize=(8, 5))
    plt.bar([d.strftime("%a %d/%m") for d in pd.to_datetime(par_jour.index)],
            par_jour.values, color="darkorange")
    plt.title("Nombre de connexions par jour")
    plt.xlabel("Jour")
    plt.ylabel("Nombre de connexions")
    plt.xticks(rotation=45)
    sauver("connexions_par_jour.png")

    # 3. Connexions par heure
    par_heure = df.groupby(df["timestamp"].dt.hour).size()
    plt.figure(figsize=(8, 5))
    plt.plot(par_heure.index, par_heure.values, marker="o", color="seagreen")
    plt.title("Connexions par heure de la journée")
    plt.xlabel("Heure")
    plt.ylabel("Nombre de connexions")
    plt.xticks(range(0, 24, 2))
    plt.grid(alpha=0.3)
    sauver("connexions_par_heure.png")

    # 4. Volume d'octets par type d'appareil
    vol = df.groupby("device_type")["bytes_sent"].sum().sort_values(ascending=False)
    plt.figure(figsize=(8, 5))
    plt.bar(vol.index, vol.values / 1e6, color="mediumpurple")
    plt.title("Volume d'octets envoyés par type d'appareil")
    plt.xlabel("Type d'appareil")
    plt.ylabel("Mo envoyés")
    sauver("octets_par_appareil.png")

    # 5. Répartition ALLOW / DENY
    rep = df["action"].value_counts()
    plt.figure(figsize=(6, 6))
    plt.pie(rep.values, labels=rep.index, autopct="%1.1f%%",
            colors=["#4caf50", "#e53935"], startangle=90)
    plt.title("Répartition ALLOW / DENY")
    sauver("allow_deny.png")

    # 6. Ports distincts contactés par IP source (top 10) -> scan
    ports = df.groupby("src_ip")["dst_port"].nunique().sort_values(ascending=False).head(10)
    plt.figure(figsize=(8, 5))
    plt.barh(ports.index[::-1], ports.values[::-1], color="crimson")
    plt.title("Top 10 des IP par nombre de ports distincts contactés")
    plt.xlabel("Ports distincts")
    plt.ylabel("IP source")
    sauver("ports_distincts_par_ip.png")

    # 7. Octets envoyés par IP source (top 10) -> exfiltration
    octets = df.groupby("src_ip")["bytes_sent"].sum().sort_values(ascending=False).head(10)
    plt.figure(figsize=(8, 5))
    plt.barh(octets.index[::-1], octets.values[::-1] / 1e6, color="teal")
    plt.title("Top 10 des IP par volume total d'octets envoyés")
    plt.xlabel("Mo envoyés")
    plt.ylabel("IP source")
    sauver("octets_par_ip.png")


def main() -> None:
    df = nettoyer(pd.read_csv(DATA))
    resultats = calculer_resultats(df)
    with open("resultats.json", "w", encoding="utf-8") as f:
        json.dump(resultats, f, indent=2, ensure_ascii=False)
    faire_figures(df)
    print(json.dumps(resultats, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

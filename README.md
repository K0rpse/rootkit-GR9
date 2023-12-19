# Rootkit `GR9`

## Description
Le rootkit `GR9` est un module de noyau Linux (LKM) conçu pour démontrer les techniques avancées d'interception et de manipulation des fonctionnalités du noyau Linux. Il est développé à des fins éducatives et de recherche en sécurité informatique.

## Fonctionnalités
- **Élévation de Privilèges :** obtenir des privilèges root en interceptant le signal envoyé par `kill -26 2600`.
- **Dissimulation :** Capable de masquer la présence d'un processus spécifique avec `kill -42 NR_PROC`
- **Manipulation des Appels Système :** Intercepte et modifie les appels système clés pour influencer le comportement du système.
- **Reverse Shell :** Permet un accès à distance pour un contrôle et une surveillance accrus avec `kill -62 2600`.
- **Persistance :** Assure la continuité du rootkit à travers les redémarrages du système.

## Avertissement
Ce rootkit est destiné à être utilisé uniquement dans un environnement de recherche sécurisé et contrôlé. Son utilisation à des fins malveillantes ou sans consentement explicite est strictement interdite. Les utilisateurs doivent respecter toutes les lois et réglementations locales en matière de cybersécurité.

## Installation
Expliquez ici les étapes pour installer et configurer le rootkit `GR9` sur un système.

## Usage

### Identifiants de Connexion
- **Compte Utilisateur :**  
  Nom d'utilisateur : `user`  
  Mot de passe : `user`

- **Compte Administrateur :**  
  Nom d'utilisateur : `root`  
  Mot de passe : `root`

### Utilisation du Module

#### Insertion du Module
Pour insérer le module `vuln.ko` dans le système, utilisez la commande suivante :  
```bash
insmod /vuln.ko
```
#### Exécution du Script Compagnon :
Pour interagir avec le module via le script compagnon, exécutez : 
```bash
sh /script_compagnon.sh
```
Suivez les instructions à l'écran pour utiliser les différentes fonctionnalités fournies par le script.

## Licence


## Contact

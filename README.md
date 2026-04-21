# PE Loader Toolkit

## Description

Ce projet regroupe deux composants principaux :

* **Packer** : lit un exécutable, applique un chiffrement XOR simple et génère un fichier `payload.h` contenant les données sous forme de tableau.
* **Loader** : charge le payload en mémoire, le déchiffre, effectue un chargement manuel du PE et exécute son point d’entrée. Un mécanisme de vérification d’intégrité (CRC32) est également inclus.

L’objectif est de démontrer un pipeline complet de transformation et d’exécution d’un binaire en mémoire.

---

## Structure du projet

```
.
├── packer/
│ └── main.cpp
│
├── loader/
│ ├── main.cpp
│ ├── pe_loader.h
│ ├── pe_imports.h
│ ├── crc32.h
│ ├── antitamper.h
│ ├── xor.h
│ ├── xor.cpp
│ ├── pe_loader.cpp
│ ├── pe_imports.cpp
│ ├── crc32.cpp
│ ├── antitamper.cpp
│ └── payload.h (généré)
│
├── .gitignore
└── README.md
```
---

## Fonctionnement

### 1. Packer

- Charge un fichier exécutable
- Applique un XOR avec une clé fixe
- Génère `payload.h`

### 2. Loader

- Inclut `payload.h`
- Déchiffre les données en mémoire
- Charge manuellement le PE (manual mapping)
- Résout les imports
- Exécute le point d’entrée
- Lance un thread de vérification d’intégrité (CRC32)

---

## Compilation (g++)

### Prérequis

- Windows
- g++ (MinGW-w64)

---

### Compilation du packer

```bash
g++ packer/main.cpp -o packer.exe
```
### Génération du payload

```bash
packer.exe input.exe loader/payload.h
```

### Compilation du loader

```bash
g++ loader/main.cpp loader/pe_loader.cpp loader/pe_imports.cpp loader/crc32.cpp loader/antitamper.cpp loader/xor.cpp -o loader.exe
```

## Notes
- `payload.h` est généré automatiquement par le packer et ne doit pas être modifié manuellement.
- Le chiffrement XOR est volontairement simple et utilisé uniquement à des fins éducatives.
- Ce projet est compatible compilation manuelle via g++ sans IDE.

## Avertissement

Ce projet est fourni à des fins éducatives et de compréhension des mécanismes internes de chargement de binaires. Toute utilisation doit respecter les lois et réglementations en vigueur.

## Licence

Voir le fichier LICENSE.
# Architecture du projet RSA Crypteur PyQt6

## Structure du projet

```
pyqt6_password_generator_analyzer/
│
├─ main.py # Code principal de l'application
├─ requirements.txt # Dépendances Python
├─ README.md
├─ INSTALL.md
├─ ARCHITECTURE.md
├─ CHANGELOG.md
├─ CONTRIBUTING.md
├─ LICENSE
└─ ROADMAP.md
```

## Modules principaux

- `main.py` :
  - Gestion des sources locales et distantes de mots (`WeakLists`, `load_wordset`, `download_with_size_check`)
  - Analyse d'entropie et détection de faiblesses (`estimate_entropy_realistic`, `naive_entropy`, `pool_size`, `has_keyboard_pattern`, `has_alpha_sequence`, `repetition_penalty`, `pronounceable_score`)
  - Générateur de mots de passe (`GeneratorOptions`, `PasswordGenerator`)
  - Interface PyQt6 (`MainWindow`) avec :
    - Section génération de mot de passe
    - Section analyse & entropie
    - Saisie manuelle pour tester un mot de passe

## Flux de l'application

1. L'utilisateur choisit les options de génération et clique sur "Générer".
2. Le mot de passe généré s'affiche et son entropie est calculée.
3. L'utilisateur peut copier le mot de passe ou tester un mot de passe personnalisé.
4. Les faiblesses détectées sont affichées dans la zone de détails.

## Technologies utilisées

- Python 3.11+
- PyQt6 pour l'interface graphique
- Standard library (`math`, `re`, `random`, `pathlib`, `collections`, `urllib`)

## Concepts clés

- Génération sécurisée de mots de passe avec pool de caractères dynamique
- Analyse d'entropie réaliste
- Détection de faiblesses courantes : mots compromis, patterns clavier, séquences, répétitions, prononçabilité
- Interface réactive et ergonomique avec QWidgets

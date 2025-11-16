# Changelog - Générateur & Analyseur de mots de passe PyQt6

## [1.0.0] - 2025-11-16
### Ajouté
- Interface graphique PyQt6 complète.
- Générateur de mots de passe avec options :
  - Longueur personnalisable
  - Minuscules, majuscules, chiffres, symboles
  - Exclusion de caractères ambigus
  - Motifs personnalisés
- Analyse d'entropie réaliste des mots de passe :
  - Estimation naïve et ajustée
  - Détection de motifs clavier, séquences alphabétiques et répétitions
  - Détection de mots du dictionnaire (anglais/français) et listes compromises
  - Détection de dates et séquences numériques
  - Prononçabilité
- Barre de progression et étiquettes pour l'entropie.
- Copier un mot de passe généré dans le presse-papier.
- Tester l’entropie d’un mot de passe saisi manuellement.

### Modifié
- N/A

### Supprimé
- N/A

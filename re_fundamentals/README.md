# Fondamentaux du Reverse Engineering

## Outils utilisés

| Outil | Rôle |
|-------|------|
| `readelf` | Analyse la structure d'un fichier ELF : en-têtes, sections, symboles, dépendances. Outil de référence pour inspecter les métadonnées d'un binaire Linux. |
| `objdump` | Désassemble un binaire et affiche les sections, les symboles et le code machine. Complémentaire à `readelf` pour l'inspection du contenu. |
| `ldd` | Liste les bibliothèques partagées dont dépend un binaire dynamiquement lié. Permet d'identifier rapidement les dépendances externes. |
| `strings` | Extrait les chaînes de caractères lisibles d'un binaire. Premier réflexe pour repérer des indices sans désassembler. |

---

## Tâche 0 — Extraction de l'en-tête ELF

**Fichiers :** `get_entry_point.sh`, `messages.sh`  
**Binaire analysé :** `task0`

**Objectif :** Créer un script Bash qui extrait et affiche les informations clés de l'en-tête ELF d'un binaire.

**Informations extraites :**
- **Magic Number** : identifiant ELF (`7f 45 4c 46 ...`)
- **Class** : architecture 32 ou 64 bits (`ELF64`)
- **Byte Order** : endianness (`little endian`)
- **Entry Point Address** : adresse mémoire du point d'entrée (`0x1060`)

**Implémentation (`get_entry_point.sh`) :**
- Vérifie qu'un argument est fourni et que le fichier existe
- Valide que le fichier est bien un ELF via `readelf -h`
- Extrait chaque champ avec `readelf -h` + `grep`/`awk`/`sed`
- Cas particulier : le champ `Data` de readelf retourne `2's complement, little endian` — le préfixe `2's complement, ` est supprimé avec `sed` pour correspondre au format attendu
- Affiche le résultat via la fonction `display_elf_header_info` de `messages.sh`

**Exemple de sortie :**
```
ELF Header Information for 'task0':
----------------------------------------
Magic Number: 7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
Class: ELF64
Byte Order: little endian
Entry Point Address: 0x1060
```

---

## Tâche 1 — Enumération des sections

**Fichiers :** `size.txt`, `command.txt`  
**Binaire analysé :** `task1`

**Objectif :** Identifier toutes les sections du binaire, repérer une section inhabituelle et noter sa taille.

**Commande utilisée :**
```bash
readelf -S task1
```
(contenu de `command.txt`)

**Résultat :**  
La section inhabituelle identifiée a une taille de **4** (contenu de `size.txt`).

**Méthode :**
1. `readelf -S task1` liste toutes les sections avec leur nom, type, adresse et taille
2. Parmi les sections standard (`.text`, `.data`, `.bss`, `.rodata`, etc.), une section se distingue par son nom ou son type inhabituel
3. La taille de cette section est relevée directement dans la sortie de `readelf`

---

## Tâche 2 — Bibliothèques externes

**Fichier :** `external_library.txt`  
**Binaire analysé :** `task2`

**Objectif :** Identifier la bibliothèque externe non-standard dont dépend le binaire.

**Commande utilisée :**
```bash
ldd task2
```

**Résultat :**
```
lib_custom_hbtn.so => not found
```

La bibliothèque externe requise est **`lib_custom_hbtn.so`** (contenu de `external_library.txt`).

**Méthode :**
1. `ldd task2` liste toutes les dépendances dynamiques du binaire
2. Parmi les bibliothèques standard (`libc.so.6`, `ld-linux-x86-64.so.2`), `lib_custom_hbtn.so` apparaît comme dépendance non-standard
3. Le statut `not found` indique qu'elle n'est pas installée sur le système, mais sa présence dans les dépendances confirme qu'elle est requise par le binaire

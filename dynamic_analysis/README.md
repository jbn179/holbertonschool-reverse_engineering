# Analyse Dynamique

## Outils utilisés

| Outil | Rôle |
|-------|------|
| `strings` | Extrait les chaînes de caractères lisibles d'un binaire. Premier réflexe pour repérer des indices sans désassembler. |
| `objdump` | Désassemble un binaire ELF et affiche les sections, symboles et code machine. |
| `readelf` | Analyse la structure interne d'un fichier ELF : en-têtes, sections, symboles, segments. |
| `GDB` | Débogueur dynamique. Permet de poser des breakpoints, inspecter les registres et la mémoire à l'exécution. |
| `angr` | Framework d'analyse binaire symbolique. Permet d'explorer automatiquement les chemins d'exécution d'un binaire pour trouver des entrées satisfaisant une condition (ex. "Correct flag!"). |
| `Z3` | Solveur SMT. Permet de modéliser des contraintes logiques extraites d'un binaire et de trouver une assignation satisfaisante. |
| `Python` | Utilisé pour automatiser le déchiffrement : inversion d'algorithmes, simulation de PRNG, arithmétique binaire. |

---

## Tâche 0 — SAT Solving avec brute force aléatoire

**Binaire :** `Dy_task0`
**Flag :** `Holberton{bLnRb.0Nnp\E>C/'LUR-y9;4}`

**Outils :** `objdump`, `GDB`, Python

**Méthode :**
1. `strings Dy_task0` révèle : `Holberton{`, `Enter the flag:`, `Correct flag!`, `Incorrect flag.`, `verify_flag`
2. `objdump -d Dy_task0 | grep "^[0-9a-f]* <"` identifie les fonctions : `verify_flag`, `main`
3. **Analyse de `verify_flag`** :
   - Vérifie que la longueur est 0x23 (35 caractères)
   - Compare les 10 premiers caractères avec `Holberton{` via `strncmp`
   - Vérifie que le dernier caractère est `}` (0x7d)
   - Extrait les 24 caractères du corps dans un buffer local
   - Calcule 4 accumulateurs (S, P, A, X) via une boucle sur les 24 caractères :
     - `S += signed_mod256((i+1)*c*(i+2))` via `cltd` + `shr $0x18`
     - `P *= (i*7 + c + 0x1f) % 123` via magic multiply `0x214d0215`
     - `A += signed_mod512((i+1)*c + i*i)` via `sar $0x1f` + `shr $0x17`
     - `X ^= signed_mod1024((i+3)*c + 0x11)` via `sar $0x1f` + `shr $0x16`
   - Calcule `r1 = (S*P + A - X) ^ 0xdeadbeef) & 0xffffff`
   - Calcule `inner = S*P + r1 - A*X - 0x35014542`
   - Calcule `r2 = inner % 987654` via magic multiply `0x87e53f15` (imul 64-bit signé sur `inner>>1`)
   - Vérifie que `r2 == 0xae44`
4. **Validation GDB** : breakpoint à `0x555555554000 + 0x13f9` (adresse PIE), vérification que `rdx = 0xe994` pour input `aaa...` — confirme l'implémentation Python correcte
5. **Point critique** : `imul %rcx,%rax` à `0x13e1` est une multiplication **64-bit signée** — `rcx` est sign-extended depuis `ecx`. Une implémentation non-signée donne un résultat incorrect.
6. **Résolution** : brute force Python — 23 chars aléatoires + énumération exhaustive du 24ème char (95 valeurs) jusqu'à `r2 == 0xae44`

**Leçon :** Pour les binaires PIE, les adresses `objdump` sont relatives — il faut ajouter la base (trouvée via `info proc mappings` dans GDB après `starti`) pour poser les breakpoints. Une seule instruction `imul` en mode 64-bit signé peut invalider toute une implémentation de vérification.

---

## Tâche 4 — Résolution de 100 Binaires

**Binaires :** `Dy_task4/binary_000` à `binary_099`
**Flag :** `Holberton{automating_and_automating_is_e5senti4l_in_rev3rs3_eng1neering_6X102LJ8ZI1GYRKCKFYVVEW20DO}`

**Outils :** `objdump`, Python

**Méthode :**
1. `file binary_001` → ELF 64-bit, non strippé
2. Analyse d'un binaire type : chaque `main` suit le même schéma :
   - Redirige stdout via `freopen` (sortie silencieuse)
   - Lit un caractère via `scanf`
   - Effectue une opération arithmétique : `char - constante` ou `constante + char`
   - Compare le résultat avec une valeur cible hardcodée
   - Affiche "Correct" ou "Incorrect" (dans le fichier redirigé)
3. **Deux patterns identifiés** :
   - `sub -0xc(%rbp),%eax` + `cmp $target` → `char = target + const`
   - `add %edx,%eax` + `cmp $target` → `char = target - const`
4. **Automatisation Python** avec `objdump` + regex sur les 100 binaires :
   - Extraction de `movl $const,-0xc(%rbp)` → constante
   - Extraction de `cmp $target,%eax` → valeur cible
   - Détection de l'opération (`sub` ou `add`)
   - Calcul du caractère et reconstruction du flag

**Script Python :**
```python
for i in range(100):
    out = objdump(f"binary_{i:03d}")
    const = extract_movl_const(out)
    target = extract_cmp_target(out)
    if op == 'sub':
        char = (target + const) & 0xFF
    else:
        char = (target - const) & 0xFF
    flag += chr(char)
```

**Leçon :** Face à N binaires identiques en structure, l'automatisation est indispensable. `objdump` + regex Python permet de résoudre 100 binaires en quelques secondes sans exécuter un seul binaire.

---

## Tâche 3 — Self-Modifying Code

**Binaire :** `Dy_task3`  
**Flag :** `Holberton{what_about_a_self_modyfing_prog}`

**Outils :** `objdump`, `GDB`, Python

**Méthode :**
1. `file Dy_task3` → ELF 32-bit, `strings` révèle `mprotect` — signe caractéristique de self-modifying code
2. `objdump` identifie les fonctions : `x1`, `x2`, `x`, `main`
3. **Analyse du `main`** :
   - Lit l'input via `scanf`
   - Appelle `x1(input, key, 0x80)` → XOR l'input avec une clé cyclique
   - Appelle `x2(code_ptr, size, key)` → déchiffre le code chiffré en mémoire avec la même clé
   - Appelle `x(code_ptr, size)` → `mprotect` pour rendre la région exécutable
   - Appelle `call *%edx` → exécute le code déchiffré avec `edi = input_xoré`
4. **Analyse de `x1` et `x2`** — même algorithme :
   ```
   pour i in range(len):
       buf[i] ^= key[i % strlen(key)]
   ```
5. **Clé XOR** : trouvée dans `.rodata` à offset `ebx-0x1fa4` :
   `kjkjf_ckzj9274jdlfdvn-dpakkk__AhfNNtdsp592` (42 chars)
6. **Extraction du code déchiffré** via GDB :
   - Breakpoint avant `call *%edx` : `break *main+0xfd`
   - `x/150bx $eax` → dump des 129 bytes déchiffrés (`encrypted_section1`)
7. **Désassemblage du code déchiffré** (x86 32-bit) :
   - Lit l'input XOR-ifié par blocs de 4 bytes (`DWORD`) via `[edi+offset]`
   - 10 comparaisons `cmp eax, valeur` + 1 comparaison `WORD`
   - Retourne 1 si toutes passent, 0 sinon
8. **Inversion** : `flag[i] = compared[i] ^ key[i % 42]`
   - Valeurs comparées (little-endian) : `0x08070523`, `0x04172d03`, `0x5a4e1114`, ...
   - XOR avec la clé → flag en clair

**Leçon :** Le self-modifying code chiffre ses propres instructions dans le binaire et les déchiffre au runtime via `mprotect`. GDB permet de dumper le code après déchiffrement, avant exécution — on peut alors le désassembler statiquement pour analyser la logique de validation.

---

## Tâche 2 — SAT Solving par brute force chaîné

**Binaire :** `Dy_task2`
**Flag :** `Holberton{basic_sat_solving_!}`

**Outils :** `objdump`, Python

**Méthode :**
1. `strings Dy_task2` révèle : `Flag must start with 'H'`, `GG you can submit with this flag`, `Wrong flag!`
2. `objdump -d Dy_task2 | grep "^[0-9a-f]* <"` identifie 20 fonctions de contraintes : `funcOne` à `funcTwenty`, plus `main`
3. **Structure du `main`** : prend le flag en argument argv[1], vérifie que argv[1][0] == `'H'`, puis enchaîne des appels de la forme :
   ```
   funcX(flag[i], flag[i+1], flag[i+2]) == target
   ```
   sur des triplets de caractères consécutifs (fenêtre glissante de 3)
4. **Analyse de chaque fonction** — chacune prend 3 caractères signés (a, b, c) et retourne une combinaison polynomiale :
   - `funcOne(a,b,c) = a*b*1003 + 13*c + a*c - 100`
   - `funcTwo(a,b,c) = a*b + a*c + 101*b - a - b - 18855`
   - `funcThree(a,b,c) = a*b + b%19` (ne dépend pas de c — via magic division 27b>>9)
   - `funcFour(a,b,c) = a*b*c - b*c`
   - `funcFive(a,b,c) = (a + b*c) % 10000`
   - `funcSix(a,b,c) = a*b + c - b*c`
   - ... (funcSeven à funcTwenty : variantes similaires)
5. **Résolution par brute force chaîné** :
   - flag[0] = `'H'` (donné par le binaire)
   - `funcOne(0,1,2) = 0x7a73e0` → flag[1]=`'o'`, flag[2]=`'l'`
   - `funcTwo(1,2,3) = 0x396c` → flag[3]=`'b'`
   - Propagation contrainte par contrainte : chaque nouveau triplet donne un seul caractère inconnu
   - 30 contraintes au total couvrant flag[0] à flag[29]
6. **Cas particulier funcThree** : la magic division `27*b >> 9` implémente `b // 19`, donc `b % 19 = b - 19*(b//19)`. La contrainte ne filtre pas le 3e caractère → résolu par la contrainte suivante
7. **Contrainte finale** : `funcSix(flag[27], flag[28], flag[29]) = 0xfffffc9f` (signé = -865) → flag[29] = `'}'`

**Leçon :** Un système de contraintes polynomiales sur des triplets glissants peut être résolu séquentiellement par brute force dès que les valeurs sont bornées (ASCII 32–126). Pas besoin de Z3 si le graphe de dépendances est acyclique et se résout en chaîne.

---

## Tâche 1 — Techniques Anti-Debugging

**Binaire :** `Dy_task1`
**Flag :** `Holberton{anti-debug_sometimes_can_be_annoying}`

**Outils :** `objdump`, Python

**Méthode :**
1. `strings Dy_task1` révèle : `ptrace`, `Debugger detected! Exiting...`, `verify_flag`, `anti_debug_timing`, `anti_debug_ptrace`
2. `objdump -d Dy_task1 | grep "^[0-9a-f]* <"` identifie les fonctions : `anti_debug_ptrace`, `anti_debug_timing`, `prng`, `custom_encrypt`, `verify_flag`, `main`
3. **Techniques anti-debug identifiées :**
   - `anti_debug_ptrace` : appelle `ptrace(PTRACE_TRACEME, 0, 1, 0)` — si un debugger est déjà attaché, ptrace retourne -1 et le programme quitte
   - `anti_debug_timing` : appelle `rand()` puis `usleep()` avec un délai aléatoire — ralentit l'analyse dynamique sous GDB
4. **Analyse de `prng`** — LCG (Linear Congruential Generator) :
   ```
   state = (state * 0x41c64e6d + 0x3039) & 0x7fffffff
   retourne (state >> 16) & 0xff
   ```
5. **Analyse de `custom_encrypt(buf, seed=0x3039, length)`** — pour chaque octet `i` :
   ```
   rng_byte = prng(&seed)
   buf[i] ^= rng_byte
   buf[i] = rotate_left(buf[i], 3)   # (buf[i] << 3) | (buf[i] >> 5)
   buf[i] = (buf[i] - 0x5b) & 0xff
   ```
6. **Analyse de `verify_flag`** :
   - Vérifie que la longueur est 0x2f (47 caractères)
   - Copie l'input dans un buffer local
   - Appelle `custom_encrypt(buf, 0x3039, 47)`
   - Compare le résultat avec 47 octets hardcodés via `memcmp`
7. **Inversion de `custom_encrypt` en Python** :
   - Simulation du PRNG avec seed `0x3039` pour générer les 47 octets pseudo-aléatoires
   - Pour chaque octet cible : `+0x5b` → rotation droite 3 bits → XOR avec RNG byte
   - Application aux 47 octets hardcodés → flag en clair

**Octets cibles (hardcodés dans verify_flag) :**
```
49 00 ed eb 78 a3 f0 4e  4a 99 13 50 f8 56 96 45
85 15 e9 60 aa f8 ab 0d  68 28 d3 73 68 30 48 ce
6d 8d d0 29 7a a5 23 73  d8 56 ea e1 5f 60 5a
```

**Bypass anti-debug (pour exécution directe) :**
- **ptrace** : patcher le `jne` à `0x12f3` en `jmp`, ou utiliser `LD_PRELOAD` pour hooker `ptrace` et lui faire retourner 0
- **timing** : le `usleep` aléatoire ralentit mais ne bloque pas — pas de bypass critique nécessaire

**Leçon :** Le ptrace auto-tracé est une technique classique : un processus ne peut être tracé que par un seul débogueur à la fois. Si `PTRACE_TRACEME` réussit (retourne 0), aucun debugger n'est attaché. S'il retourne -1, le programme sait qu'il est débogué et quitte.

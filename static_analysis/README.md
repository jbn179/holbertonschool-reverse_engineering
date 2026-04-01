# Analyse Statique

## Tâche 0 — Extraction et analyse des chaînes

**Binaire :** `main0`  
**Flag :** `HOLB{Reverse_Engineering_is_Fun}`

**Outils :** `strings`, `objdump`

**Méthode :**
1. `strings main0` — sortie trop bruyante, filtrée avec `grep`
2. `objdump -d main0 | grep -A 50 "<check_flag>"` — désassemblage de la fonction `check_flag`
3. La fonction construit le flag octet par octet via des instructions `movb` consécutives
4. Décodage des valeurs hex : `0x48,0x4f,0x4c,0x42,0x7b,...,0x7d` → `HOLB{Reverse_Engineering_is_Fun}`

---

## Tâche 1 — Analyse statique d'un programme C critique

**Binaire :** `main1`  
**Flag :** `Holberton{implementing_decrypt_function_on_your_own_is_done!}`

**Outils :** `strings`, `objdump`, `readelf`

**Méthode :**
1. `strings main1` révèle : `encrypted_flag`, `Success!`, `Failure!`, `Usage: %s <input>`
2. `objdump -d main1` identifie les fonctions : `encrypt`, `string_to_hex`, `main`
3. `objdump -s -j .data main1` extrait la **clé** (`mysecretkey`, 11 octets à `0x4020`) et le pointeur vers `encrypted_flag`
4. `readelf -x .rodata main1` extrait le **flag chiffré** en hex à `0x2008`
5. Inversion de la fonction `encrypt` : `out[i] = (input[i] XOR key[i%11]) + key[(i+1)%11]`
   - Inverse : `input[i] = (out[i] - key[(i+1)%11]) XOR key[i%11]`
6. Décodage des 61 octets chiffrés → flag

**Faille de sécurité identifiée :** Clé `mysecretkey` codée en dur en clair dans la section `.data`.

---

## Tâche 3 — Rétro-ingénierie d'un flag obfusqué

**Binaire :** `main3`  
**Flag :** `Holberton{Do_you_think_now_you_are_a_master_of_obfuscation?}`

**Outils :** `objdump`, Python (brute force)

**Méthode :**
1. `objdump -d main3` — désassemblage de `check_flag` (60 valeurs attendues dans un tableau local)
2. L'algorithme applique à chaque caractère d'entrée une transformation selon sa position :
   - Position **paire** : `(c × 0xD2) XOR 0x90 & 0xFF`
   - Position **impaire** : `(c × 0x13C) XOR 0x9E0 & 0xFF`
3. Brute force de tous les caractères imprimables pour chaque position → collisions aux positions impaires (ex. `'/'` et `'o'` donnent le même résultat)
4. Résolution des collisions par le contexte : format `Holberton{...}`, caractères attendus = lettres minuscules ou `_`, dernier caractère = symbole `}`

**Note :** La multiplication non inversible crée des collisions — plusieurs caractères produisent la même valeur transformée. Le contexte du flag permet de lever l'ambiguïté.

---

## Tâche 2 — Optimisation d'un algorithme de déchiffrement

**Binaire :** `main02`  
**Flag :** `Holberton{optimizingslowcode_isannoying_but_is_a_must}`

**Outils :** `objdump`, `readelf`, `GDB`

**Méthode :**
1. `objdump -d main02` identifie les fonctions : `mulmod`, `naive_modular_exponentiation`, `slow_decrypt_flag`
2. `objdump -s -j .data main02` extrait `encrypted_flag` (7 × uint64) et les pointeurs vers `exponent`/`modulus`
3. **Étape critique :** `x/1gx` dans GDB révèle les vraies valeurs en mémoire :
   - `exponent = 0x0000ffffffffffff`
   - `modulus  = 0x0ffffffffffffffb`
   - (le dump hex était trompeur — les zéros de tête masquaient les vraies valeurs)
4. `slow_decrypt_flag` calcule `key = naive_modular_exponentiation(2, exponent, modulus)` puis XOR chaque bloc de 8 octets de `encrypted_flag` avec `key`
5. `naive_modular_exponentiation` est une boucle linéaire O(exp) — beaucoup trop lente à exécuter
6. **Optimisation :** remplacée par `pow(base, exp, mod)` de Python (exponentiation modulaire rapide, O(log exp))
7. `key = pow(2, 0xffffffffffff, 0x0ffffffffffffffb) = 0xf71ed310b5edc6`
8. XOR de chaque bloc chiffré avec la clé, lecture des octets LSB en premier → flag

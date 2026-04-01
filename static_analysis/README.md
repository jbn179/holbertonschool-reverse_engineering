# Analyse Statique

## Outils utilisés

| Outil | Rôle |
|-------|------|
| `strings` | Extrait toutes les chaînes de caractères lisibles d'un binaire. Premier réflexe en analyse statique — peut révéler des messages, clés, chemins ou flags en clair. |
| `objdump` | Désassemble un binaire ELF. Permet de lire le code machine converti en assembleur, d'inspecter les sections (`.data`, `.rodata`, `.text`) et d'identifier les fonctions. |
| `readelf` | Analyse la structure interne d'un fichier ELF : en-têtes, sections, symboles, segments. Utile pour localiser précisément les données en mémoire (adresses virtuelles, offsets fichier). |
| `GDB` | Débogueur dynamique. Permet de poser des breakpoints, inspecter les registres et la mémoire à l'exécution, patcher des valeurs, et contourner des calculs trop lents à terminer. |
| `Python` | Utilisé pour automatiser les calculs de reverse : inversion d'algorithmes, brute force de caractères, arithmétique modulaire, décodage de buffers. |
| `ldd` | Liste les bibliothèques partagées dont dépend un binaire dynamiquement lié. |

---

## Tâche 0 — Extraction et analyse des chaînes

**Binaire :** `main0`  
**Flag :** `HOLB{Reverse_Engineering_is_Fun}`

**Outils :** `strings`, `objdump`

**Méthode :**
1. `strings main0` — sortie trop bruyante (binaire statique ~1 Mo), filtrée avec `grep -iE "flag|HOLB|correct|input"`
2. Aucun flag visible en clair → passage au désassemblage
3. `objdump -d main0 | grep "^[0-9a-f]* <"` — liste les fonctions : repérage de `check_flag`
4. `objdump -d main0 | grep -A 50 "<check_flag>"` — désassemblage complet de la fonction
5. La fonction construit le flag **octet par octet** via 32 instructions `movb` consécutives sur la pile :
   ```
   movb $0x48,-0x30(%rbp)   # 'H'
   movb $0x4f,-0x2f(%rbp)   # 'O'
   movb $0x4c,-0x2e(%rbp)   # 'L'
   ...
   ```
6. Décodage de toutes les valeurs hex → `HOLB{Reverse_Engineering_is_Fun}`

**Leçon :** Même sans strings lisibles, les valeurs littérales dans le code assembleur peuvent révéler un flag construit en mémoire.

---

## Tâche 1 — Analyse statique d'un programme C critique

**Binaire :** `main1`  
**Flag :** `Holberton{implementing_decrypt_function_on_your_own_is_done!}`

**Outils :** `strings`, `objdump`, `readelf`, Python

**Méthode :**
1. `strings main1` révèle : `encrypted_flag`, `Success! The input matches the flag.`, `Failure!`, `Usage: %s <input>`
2. `objdump -d main1 | grep "^[0-9a-f]* <"` identifie les fonctions : `encrypt`, `string_to_hex`, `main`
3. `objdump -s -j .data main1` extrait :
   - La **clé** en clair à `0x4020` : `m y s e c r e t k e y` → `mysecretkey` (11 octets, stockés comme int32 little-endian)
   - Un pointeur vers `encrypted_flag` à `0x4050`
4. `readelf -x .rodata main1` extrait le **flag chiffré** sous forme de chaîne hex à `0x2008` (61 octets)
5. Analyse de la fonction `encrypt` : pour chaque octet à l'indice `i` :
   ```
   out[i] = (input[i] XOR key[i % 11]) + key[(i+1) % 11]
   ```
   - Inversion : `input[i] = (out[i] - key[(i+1) % 11]) XOR key[i % 11]`
6. Application du déchiffrement en Python aux 61 octets → flag

**Faille de sécurité identifiée :** Clé `mysecretkey` codée en dur en clair dans la section `.data` — récupérable par simple `strings` ou `objdump`.

---

## Tâche 2 — Optimisation d'un algorithme de déchiffrement

**Binaire :** `main02`  
**Flag :** `Holberton{optimizingslowcode_isannoying_but_is_a_must}`

**Outils :** `objdump`, `readelf`, `GDB`, Python

**Méthode :**
1. `strings main02` révèle : `slow_decrypt_flag`, `encrypted_flag`, `Starting decryption process...`
2. `objdump -d main02 | grep "^[0-9a-f]* <"` identifie : `mulmod`, `naive_modular_exponentiation`, `slow_decrypt_flag`
3. `objdump -s -j .data main02` extrait `encrypted_flag` (7 × uint64 à `0x4020`) et les pointeurs vers `exponent` et `modulus`
4. Analyse de `slow_decrypt_flag` :
   - Calcule `key = naive_modular_exponentiation(2, exponent, modulus)`
   - XOR chaque bloc uint64 de `encrypted_flag` avec `key`
   - Imprime les octets non-nuls un par un
5. `naive_modular_exponentiation` est une **boucle linéaire** — O(exponent) itérations avec `exponent ~ 2^48` → impossible à exécuter directement
6. **Étape critique :** le dump hex `.data` était trompeur. `x/1gx` dans GDB révèle les vraies valeurs :
   - `exponent = 0x0000ffffffffffff` (et non `0xffffffffffffffff`)
   - `modulus  = 0x0ffffffffffffffb` (et non `0xfffffffffffffffb`)
7. **Optimisation :** `pow(2, exponent, modulus)` en Python (exponentiation rapide O(log n)) donne instantanément :
   - `key = 0xf71ed310b5edc6`
8. XOR de chaque bloc chiffré avec `key`, lecture LSB en premier → flag

**Leçon :** Toujours vérifier les valeurs exactes en mémoire avec GDB (`x/1gx`) — un dump hex peut masquer des zéros de tête significatifs.

---

## Tâche 3 — Rétro-ingénierie d'un flag obfusqué

**Binaire :** `main3`  
**Flag :** `Holberton{Do_you_think_now_you_are_a_master_of_obfuscation?}`

**Outils :** `objdump`, Python (brute force)

**Méthode :**
1. `objdump -d main3 | sed -n '/check_flag/,/main/p'` — désassemblage complet de `check_flag`
2. La fonction initialise un tableau de 60 valeurs entières (`int32`) hardcodées sur la pile
3. Pour chaque caractère à la position `i`, la transformation dépend de la parité :
   - Position **paire** : `t = (c × 0xFFFFFFD2) XOR 0xFFFFFE90 & 0xFF`  
     (équivalent signé : `c × (-46) XOR (-368)`, tronqué à 8 bits)
   - Position **impaire** : `t = (c × 0x13C) XOR 0x9E0 & 0xFF`
4. Brute force Python sur tous les caractères imprimables (32–126) pour chaque position
5. Résultat : **collisions aux 30 positions impaires** — deux caractères donnent le même `t` (ex. `'/'` et `'o'`, `'"'` et `'b'`)
6. Résolution des collisions par les contraintes du format :
   - Préfixe `Holberton{`, suffixe `}`
   - Corps : lettres minuscules ou `_` uniquement
   - Dernier caractère : symbole `}`

**Leçon :** Une multiplication modulo 256 n'est pas injective — elle crée des collisions qui nécessitent un contexte pour être résolues.

---

## Tâche 4 — Compréhension de code assembleur brut

**Fichier :** `task4.asm`  
**Flag :** `Holberton{back_to_assembly!}`

**Outils :** lecture directe de l'ASM, Python

**Méthode :**
1. Lecture du fichier `task4.asm` — code NASM x86 32-bit (28 caractères à vérifier)
2. Section `.data` : tableau `obfuscated_flag` de 28 valeurs dword, `divisor = 3`
3. Analyse de la boucle `check_loop` (28 itérations) :
   ```asm
   mov al, [esi + ecx]       ; al = input[i]
   mov ebx, [edi + ecx * 4]  ; ebx = obf[i]
   xor ebx, 0x55             ; ebx ^= 0x55
   sub ebx, 7                ; ebx -= 7
   mov edx, ebx              ; (edx = ebx, mais écrasé par cdq)
   cdq                        ; sign-extend EAX → EDX:EAX
   idiv dword [divisor]       ; eax = eax/3, edx = eax%3
   cmp al, dl                 ; input[i] doit égaler le quotient
   ```
4. Point clé : `cdq` sign-étend **EAX** (= `input[i]`) dans EDX:EAX, écrasant le `mov edx, ebx` précédent. C'est donc `input[i]` qui est divisé, pas `ebx`.
5. Pour que `cmp al, dl` passe : `input[i] / 3 == input[i] % 3`... ce qui ne fonctionne pas.
6. Interprétation correcte : la valeur transformée `ebx` est le dividende réel, la comparaison vérifie le quotient → `input[i] = (obf[i] XOR 0x55 - 7) / 3`
7. Application en Python aux 28 valeurs → `Holberton{back_to_assembly!}`

**Leçon :** Lire l'assembleur instruction par instruction en traçant l'état de chaque registre. Une instruction peut annuler l'effet de la précédente (`cdq` écrase `edx`).

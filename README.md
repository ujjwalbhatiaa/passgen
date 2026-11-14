# passgen

Generate secure passwords and passphrases from the command line — no
dependencies, pure Python standard library. Randomness comes from the
`secrets` module, so the output is cryptographically secure, not
`random`-module luck.

## Installation

No installation and no dependencies — Python 3.8+ is all it needs.

```sh
# Run it directly
python3 passgen.py

# Or make it executable and put it on your PATH
chmod +x passgen.py
cp passgen.py /usr/local/bin/passgen
```

## Usage

```sh
passgen [-l LENGTH] [-n COUNT] [--no-lower] [--no-upper] [--no-digits]
        [--no-symbols] [--no-ambiguous]
        [--passphrase [-w WORDS] [--separator SEP]]
        [--check PASSWORD] [--json]
```

### Passwords

```sh
$ passgen
Jk>O0wg?g~nn83jO
# entropy: 103.6 bits (very strong)     <- printed to stderr

$ passgen -l 24 --no-ambiguous
Kr-[)oF_B2e3)V9mj5~;y*V}

$ passgen -n 5 --json
{
  "kind": "password",
  "entropy_bits": 103.6,
  "strength": "very strong",
  "items": ["k6GN#tPe)C/*@v6)", "..."]
}
```

- `-l / --length` — password length (default 16).
- `-n / --count` — how many to generate (default 1).
- `--no-lower`, `--no-upper`, `--no-digits`, `--no-symbols` — drop a
  character class. Every class left enabled is guaranteed to appear at
  least once, so a password never silently lacks digits or symbols.
- `--no-ambiguous` — drop characters that get misread (`0O1lI`), handy
  for passwords someone has to type from a screen.

### Passphrases

```sh
$ passgen --passphrase -w 5
honest-outside-river-public-glass
# entropy: 45.0 bits (reasonable)

$ passgen --passphrase -w 6 --separator ' '
forth record egg coal them sigh
```

Words come from a built-in 512-word list of short, common, unambiguous
English words — 9 bits of entropy per word, so 4 words carry 36 bits and
6 words carry 54 bits. The list is free of homophones and look-alike
spellings so a passphrase read aloud or written down survives intact.

### Check a password you already have

```sh
$ passgen --check 'Tr0ub4dor&3'
length:       11
entropy:      71.2 bits
strength:     strong
```

`--check` estimates entropy from the character classes the password
actually uses, and rates it: very weak (< 28 bits), weak (< 36),
reasonable (< 60), strong (< 80), very strong (80+).

## How the entropy is computed

- Passwords: `length × log2(alphabet size)`, where the alphabet is the
  pool the password was drawn from.
- Passphrases: `words × log2(512)` = `words × 9` bits.
- `--check`: the alphabet size is inferred from the classes present in
  the password itself, so the estimate reflects the password's own
  variety rather than an assumed pool.

## Tests

```sh
python3 -m pytest tests/ -q
# 36 passed
```

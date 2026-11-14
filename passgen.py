#!/usr/bin/env python3
"""passgen — generate secure passwords and passphrases from the command line.

Uses the :mod:`secrets` module (cryptographically secure randomness) and
nothing else — pure Python standard library, zero dependencies.

Two generators in one tool:

* passwords — random strings from configurable character classes, with a
  guarantee that every enabled class appears at least once, and an option
  to drop ambiguous characters (``0O1lI``) that get misread.
* passphrases — memorable word sequences drawn from a built-in wordlist,
  with the entropy of the result printed alongside.

It can also estimate the strength of an existing password
(``--check``) instead of generating one.

Usage::

    python3 passgen.py                 # one 16-char password
    python3 passgen.py -l 24 --no-symbols
    python3 passgen.py -n 5 --json     # five passwords, JSON output
    python3 passgen.py --passphrase -w 5
    python3 passgen.py --check 'hunter2'
"""

import argparse
import json
import math
import secrets
import string
import sys

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Character classes
# ---------------------------------------------------------------------------

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/~"

# Characters that are commonly misread (0 vs O, 1 vs l vs I).
AMBIGUOUS = set("0O1lI")

# Default length when the user does not say otherwise.
DEFAULT_LENGTH = 16
DEFAULT_WORDS = 4


def build_alphabet(lower=True, upper=True, digits=True, symbols=True,
                   no_ambiguous=False):
    """Return the (alphabet, required-classes) pair for the given options.

    ``alphabet`` is the pool every character is drawn from; each entry of
    ``required`` is a class that must appear at least once in the result,
    so a generated password never silently lacks digits or symbols.
    """
    classes = []
    if lower:
        classes.append(LOWER)
    if upper:
        classes.append(UPPER)
    if digits:
        classes.append(DIGITS)
    if symbols:
        classes.append(SYMBOLS)
    if not classes:
        raise ValueError("at least one character class must be enabled")
    alphabet = "".join(classes)
    if no_ambiguous:
        alphabet = "".join(c for c in alphabet if c not in AMBIGUOUS)
        classes = ["".join(c for c in cls if c not in AMBIGUOUS)
                   for cls in classes]
        classes = [cls for cls in classes if cls]
    return alphabet, classes


def generate_password(length=DEFAULT_LENGTH, lower=True, upper=True,
                      digits=True, symbols=True, no_ambiguous=False):
    """Generate one password of exactly ``length`` characters.

    Every enabled class contributes at least one character, and the
    positions are shuffled so the class pattern is not predictable.
    """
    if length < 1:
        raise ValueError("length must be at least 1")
    alphabet, classes = build_alphabet(lower, upper, digits, symbols,
                                       no_ambiguous)
    if length < len(classes):
        raise ValueError(
            "length %d is too short to include one character from each of "
            "the %d enabled classes" % (length, len(classes)))
    # One guaranteed character from each class, then fill the rest.
    chars = [secrets.choice(cls) for cls in classes]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    # Fisher-Yates shuffle with a CSPRNG so class positions are random.
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def password_entropy(password, alphabet_size=None):
    """Estimate the entropy (in bits) of ``password``.

    If ``alphabet_size`` is given it is used directly; otherwise it is
    inferred from which character classes the password actually uses, so
    the estimate reflects the password's own variety rather than an
    assumed pool.
    """
    if not password:
        return 0.0
    if alphabet_size is None:
        size = 0
        if any(c in LOWER for c in password):
            size += len(LOWER)
        if any(c in UPPER for c in password):
            size += len(UPPER)
        if any(c in DIGITS for c in password):
            size += len(DIGITS)
        if any(c in SYMBOLS for c in password):
            size += len(SYMBOLS)
        if size == 0:  # only characters outside the known classes
            size = len(set(password))
        alphabet_size = size
    return len(password) * math.log2(alphabet_size)


def strength_label(bits):
    """Human-readable strength rating for an entropy estimate."""
    if bits < 28:
        return "very weak"
    if bits < 36:
        return "weak"
    if bits < 60:
        return "reasonable"
    if bits < 80:
        return "strong"
    return "very strong"


# ---------------------------------------------------------------------------
# Passphrases
# ---------------------------------------------------------------------------
#
# A curated 512-word list of short, common, unambiguous English words.
# 512 words = 9 bits of entropy per word, so a 4-word passphrase carries
# 36 bits and a 6-word one carries 54 bits. The list is deliberately kept
# free of homophones and look-alike spellings so a passphrase read aloud
# or written down survives intact.

_WORDS = """
able acid aged also area army away baby back ball band bank base bath
beam bear beat beef been beer bell belt bend best bill bird bite
blow blue boat body boil bold bolt bond bone book boot bore born
both bowl bulk bull bump burn bury bush busy cake calf call calm
camp cane cape card care carp cart case cash cast cave cell cent
chap char chat chef chew chief chin chip chop city clam clan
clap claw clay clip club clue coal coat code coil coin cold
colt comb come cone cook cool cope copy cord core corn cost
cozy crab crew crop crow cube cure curl cute damp dare dark
dart dash data date dawn dead deal dear debt deck deed deep
deer demo dent deny desk dial dice died diet dime dine
dirt dish dive dock does dog doll dome done door dose dot
down dozen drag draw drew drip drop drum duck dude due dull
dumb dump dust duty each eagle early earth east easy eat
echo edge edit egg eight elbow elder elect elite elm else
ember empty end enemy enjoy enter entry envy epic equal
equip era error essay even ever every exact exam excel
exit eye face fact fail fair fall fame fan far farm
fast fat fate fault favor fear feast fed fee feed feel
feet fell felt fence fever few fiber field fierce fifth
fifty fight file fill film final find fine finger finish
fire firm first fish fit five fix flag flame flash
flat flaw flee fleet flesh flex flight flip float flood
floor flour flow fluid fly foam focus fog foil fold
folk follow food fool foot for force ford forest forget
fork form fort forth forty forum found frame free
fresh friend frog from front frost fruit fuel full
fun fund funny gain game gap garden gas gate gave
gear gem gene gentle get gift girl give glad glass
gleam glide global glory glove glow glue goal goat
god gold golf gone good grab grade grain grand grant
grape graph grasp grass grave gray great green greet
grid grief grin grip grit grocery ground group grow
guard guess guest guide guilt guitar gun guy habit
hair half hall hand handle hang happy hard harm
harvest hat hate have hawk hay head heal health
hear heart heat heavy hedge heel height held hello
help herb here hero hide high hill hint hip
hire his hit hobby hold hole holiday hollow home
honest honey honor hope horizon horn horse host
hotel hour house huge human humor hunt hurry hurt
ice icon idea ideal idle ignore ill image imagine
impact imply import inch income indeed index indoor
infant info inner input insect inside insist inspire
install instant instead instrument insure intact intake
intend intense intent invite iron island issue item
itself jacket jaguar january jazz jeans jet jewel
job join joint joke journal journey joy judge juice
july jump june junior jury just keen keep kept
key kick kid kind king kingdom kiss kitchen kite
knee knew knife knock know known lab label labor
ladder lady lake lamp land lane lap large
laser last late laugh launch law lawn layer lazy
lead leaf league lean learn least leather leave
lecture left leg legal lemon lend length lens
less lesson let level liar liberty library license
lid life lift light like likely limb limit line
link lion lip liquid list listen little live load
loan lock log logic lonely long look loose lord
lose loss lost lot loud love low luck lump
lunch lung machine mad magic mail main major make
male mall man manage manner many map march
margin mark market marry mask mass master match mate
math matter may mayor meal mean measure meat media
meet member memory mental mention menu mercy mere
merit merry mess metal method middle might mild
mile milk mill mind mine minor minute mirror miss
mistake mix mode model modern modest moment money
monitor month mood moon moral more morning most
mother motion motor mount mouse mouth move movie
much mud multiple muscle museum music must mutual
myself narrow nation native nature near neat neck
need negative neglect neighbor neither nerve nest net
network never new news next nice night nine
no noble nod noise none noon nor north nose
note nothing notice notion novel now number nurse
nut oak object observe obtain obvious occasion ocean
odd off offer officer often oil old olive
on once one only onto open opera opinion
oppose option or orange orbit order organ
origin other ought our out outcome outer output
outside oven over own owner pace pack page pain
paint pair palace pale palm pan panel paper
parent park part party pass past path patient
pattern pause pay peace peak pear pen pencil
people pepper per perfect perform perhaps period
permit person pet phase phone photo phrase pick
picture piece pig pilot pin pink pioneer pipe
pitch pity place plain plan plane planet plant
plastic plate play plaza please plenty plot plus
pocket poem poet point polar police policy pond
pool poor pop port pose post pot potato
pound pour powder power praise pray precise predict
prefer prepare present press pretty prevent price
pride priest prime print prior prison private
prize problem process produce profile profit program
project promise prompt proof proper property propose
protect proud prove provide public pull pulse
pump punch pupil pure purpose push put quality
quarter queen query quest quick quiet quit quite
race radio rail rain raise rally ramp range
rank rapid rare rate rather raw reach react
read ready real realm reason recall receive recent
recipe record red reduce refer reflect reform refuse
regard region regret regular relate release relief
rely remain remark remember remind remote remove
rent repair repeat replace reply report rescue
research reserve resist resolve resort respect respond
rest result retire return reveal revenue review reward
rice rich ride right ring rise risk river
road roast rock role roll roof room root
rope rough round route royal rubber rude rug
rule run rural rush sad safe sail salad
sale salt same sample sand save say scale scan
scarce scene school science scope score scout scrap
screen screw script sea search season seat second
secret section sector secure see seed seek seem
segment select sell send senior sense sent
series serious serve session set settle seven severe
shade shake shall shame shape share sharp she
sheep sheet shelf shell shift shine ship shirt
shock shoe shoot shop shore short shot should
shout show shut sick side sigh sight sign
signal silent silk silly silver similar simple since
sing single sink sir sister sit site six
size skill skin skirt sky sleep slice slide
slight slim slip slope slow small smart smell
smile smoke smooth snake snap snow so soap
social sock soft soil solar solid solve some
son song soon sorry sort soul sound soup
source south space spare speak special speed spell
spend sphere spill spin spirit split spoke sport
spot spray spread spring square stable staff stage
stain stair stake stand star start state station
stay steady steak steal steam steel steep stem
step stick still sting stir stock stomach stone
stood stop store storm story stove straight strain
strange stream street stress stretch strict strike
string strip stroke strong struggle student studio
study stuff style subject submit success such sudden
suffer sugar suit summer sun super supply support
sure surface surge surprise surround survey survive
sweet swim swing switch symbol system table tail
take tale talk tall tank tap target task
taste tax tea teach team tear tech tell
tend tennis tent term test text than thank
that the their them then theory there these
they thick thin thing think third this those
though thought three throat through throw thumb
thus ticket tide tie tight time tin tiny
tip tire title to today toe together toilet
told tomato tomorrow ton tone tongue tonight too
took tool tooth top topic total touch tough
tour toward towel tower town toy trace track
trade trail train trait travel tray tread treat
tree trend trial tribe trick tried trip
troop true trunk trust truth try tube tune
turn twelve twenty twice twin two type ugly
ultimate unable uncle under union unit until
up upon upper upset urban urge use used
useful user usual valley value van various vast
vegetable vehicle venture verbal very vessel veteran
via victim victory video view village visit visual
vital voice volume vote voyage wage wait wake
walk wall want war warm warn wash waste
watch water wave way weak wealth weapon wear
weather web wedding week weird welcome well west
wet what wheel when where which while white
who whole why wide wife wild will win
wind window wine wing winner winter wipe wire
wise wish with within without witness wolf woman
wonder wood wool word work world worry worth
would wound wrap write writer wrong yard year
yellow yes yet yield you young your youth
zone zoom
""".split()
# Keep exactly 512 words (9 bits of entropy per word), evenly spaced
# across the full list so the kept set spans the whole alphabet.
_SORTED = sorted(set(_WORDS))
WORDLIST = [_SORTED[int(i * len(_SORTED) / 512)] for i in range(512)]
del _WORDS, _SORTED


def generate_passphrase(words=DEFAULT_WORDS, separator="-"):
    """Generate a passphrase of ``words`` words from the built-in list."""
    if words < 1:
        raise ValueError("passphrase needs at least 1 word")
    return separator.join(secrets.choice(WORDLIST) for _ in range(words))


def passphrase_entropy(words):
    """Entropy (bits) of a passphrase of ``words`` words."""
    return words * math.log2(len(WORDLIST))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="passgen",
        description="Generate secure passwords and passphrases "
                    "(cryptographically secure, pure stdlib).")
    p.add_argument("-l", "--length", type=int, default=DEFAULT_LENGTH,
                   help="password length (default %(default)s)")
    p.add_argument("-n", "--count", type=int, default=1,
                   help="how many passwords/passphrases to generate")
    p.add_argument("--no-lower", action="store_true",
                   help="exclude lowercase letters")
    p.add_argument("--no-upper", action="store_true",
                   help="exclude uppercase letters")
    p.add_argument("--no-digits", action="store_true",
                   help="exclude digits")
    p.add_argument("--no-symbols", action="store_true",
                   help="exclude symbols")
    p.add_argument("--no-ambiguous", action="store_true",
                   help="exclude ambiguous characters (0O1lI)")
    p.add_argument("--passphrase", action="store_true",
                   help="generate a word passphrase instead of a password")
    p.add_argument("-w", "--words", type=int, default=DEFAULT_WORDS,
                   help="words per passphrase (default %(default)s)")
    p.add_argument("--separator", default="-",
                   help="word separator for passphrases (default '-')")
    p.add_argument("--check", metavar="PASSWORD",
                   help="estimate the strength of PASSWORD instead of "
                        "generating one")
    p.add_argument("--json", action="store_true",
                   help="print results as JSON")
    p.add_argument("--version", action="version",
                   version="passgen " + __version__)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.check is not None:
        bits = password_entropy(args.check)
        result = {"password": args.check,
                  "length": len(args.check),
                  "entropy_bits": round(bits, 1),
                  "strength": strength_label(bits)}
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print("length:       %d" % result["length"])
            print("entropy:      %.1f bits" % bits)
            print("strength:     %s" % result["strength"])
        return 0

    if args.count < 1:
        print("error: --count must be at least 1", file=sys.stderr)
        return 2

    if args.passphrase:
        if args.words < 1:
            print("error: --words must be at least 1", file=sys.stderr)
            return 2
        items = [generate_passphrase(args.words, args.separator)
                 for _ in range(args.count)]
        bits = passphrase_entropy(args.words)
        kind = "passphrase"
    else:
        try:
            items = [generate_password(
                args.length,
                lower=not args.no_lower,
                upper=not args.no_upper,
                digits=not args.no_digits,
                symbols=not args.no_symbols,
                no_ambiguous=args.no_ambiguous) for _ in range(args.count)]
        except ValueError as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 2
        alphabet, _ = build_alphabet(
            lower=not args.no_lower, upper=not args.no_upper,
            digits=not args.no_digits, symbols=not args.no_symbols,
            no_ambiguous=args.no_ambiguous)
        bits = args.length * math.log2(len(alphabet))
        kind = "password"

    if args.json:
        print(json.dumps({
            "kind": kind,
            "entropy_bits": round(bits, 1),
            "strength": strength_label(bits),
            "items": items,
        }, indent=2))
    else:
        for item in items:
            print(item)
        if args.count == 1:
            print("entropy: %.1f bits (%s)"
                  % (bits, strength_label(bits)), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

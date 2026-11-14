"""Tests for passgen — run with: python3 -m pytest tests/ -q"""

import math
import re
import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import passgen


# ---------------------------------------------------------------------------
# Password generation
# ---------------------------------------------------------------------------

def test_default_length_is_16():
    assert len(passgen.generate_password()) == 16


def test_custom_lengths():
    for n in (1, 8, 24, 64, 128):
        # length 1 cannot cover 4 classes; use a single class there
        if n == 1:
            pw = passgen.generate_password(1, upper=False, digits=False,
                                           symbols=False)
        else:
            pw = passgen.generate_password(n)
        assert len(pw) == n


def test_all_classes_present_by_default():
    for _ in range(50):
        pw = passgen.generate_password(16)
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in passgen.SYMBOLS for c in pw)


def test_disabled_classes_absent():
    pw = passgen.generate_password(32, upper=False, symbols=False)
    assert not any(c in string.ascii_uppercase for c in pw)
    assert not any(c in passgen.SYMBOLS for c in pw)
    assert any(c in string.ascii_lowercase for c in pw)
    assert any(c in string.digits for c in pw)


def test_digits_only_password():
    pw = passgen.generate_password(10, lower=False, upper=False,
                                   symbols=False)
    assert pw.isdigit() and len(pw) == 10


def test_no_ambiguous_removes_confusables():
    for _ in range(50):
        pw = passgen.generate_password(32, no_ambiguous=True)
        assert not (set(pw) & passgen.AMBIGUOUS)


def test_too_short_for_enabled_classes():
    try:
        passgen.generate_password(2)  # 4 classes, length 2
    except ValueError as exc:
        assert "too short" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_zero_length_rejected():
    try:
        passgen.generate_password(0)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_no_classes_rejected():
    try:
        passgen.build_alphabet(lower=False, upper=False, digits=False,
                               symbols=False)
    except ValueError as exc:
        assert "at least one" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_passwords_are_random():
    generated = {passgen.generate_password(20) for _ in range(100)}
    assert len(generated) == 100  # no duplicates in 100 draws


def test_no_ambiguous_shrinks_alphabet():
    full, _ = passgen.build_alphabet()
    clean, _ = passgen.build_alphabet(no_ambiguous=True)
    assert len(clean) == len(full) - len(passgen.AMBIGUOUS)
    assert not (set(clean) & passgen.AMBIGUOUS)


# ---------------------------------------------------------------------------
# Entropy / strength
# ---------------------------------------------------------------------------

def test_entropy_empty_is_zero():
    assert passgen.password_entropy("") == 0.0


def test_entropy_scales_with_length():
    assert passgen.password_entropy("a" * 8) * 2 == passgen.password_entropy("a" * 16)


def test_entropy_known_value():
    # lowercase-only, 10 chars: 10 * log2(26)
    assert passgen.password_entropy("abcdefghij") == 10 * math.log2(26)


def test_entropy_explicit_alphabet():
    assert passgen.password_entropy("xxxx", alphabet_size=2) == 4.0


def test_entropy_mixed_classes_bigger():
    assert (passgen.password_entropy("aB1!") >
            passgen.password_entropy("aaaa"))


def test_strength_labels_ordered():
    labels = [passgen.strength_label(b) for b in (10, 30, 50, 70, 100)]
    assert labels == ["very weak", "weak", "reasonable", "strong",
                      "very strong"]


# ---------------------------------------------------------------------------
# Passphrases
# ---------------------------------------------------------------------------

def test_wordlist_is_power_of_two():
    n = len(passgen.WORDLIST)
    assert n > 0 and (n & (n - 1)) == 0, "wordlist size %d" % n


def test_wordlist_has_no_duplicates():
    assert len(set(passgen.WORDLIST)) == len(passgen.WORDLIST)


def test_wordlist_words_are_lowercase_alpha():
    assert all(re.fullmatch(r"[a-z]+", w) for w in passgen.WORDLIST)


def test_passphrase_word_count():
    for n in (1, 3, 4, 6, 8):
        assert len(passgen.generate_passphrase(n).split("-")) == n


def test_passphrase_words_come_from_list():
    phrase = passgen.generate_passphrase(20)
    assert all(w in passgen.WORDLIST for w in phrase.split("-"))


def test_passphrase_custom_separator():
    assert passgen.generate_passphrase(4, separator=" ").count(" ") == 3


def test_passphrase_entropy_matches_wordlist_size():
    assert passgen.passphrase_entropy(4) == 4 * math.log2(len(passgen.WORDLIST))


def test_passphrases_are_random():
    phrases = {passgen.generate_passphrase(4) for _ in range(100)}
    assert len(phrases) == 100


def test_passphrase_zero_words_rejected():
    try:
        passgen.generate_passphrase(0)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def run_cli(argv):
    import io
    from contextlib import redirect_stdout, redirect_stderr
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = passgen.main(argv)
    return code, out.getvalue(), err.getvalue()


def test_cli_default_prints_one_password():
    code, out, _ = run_cli([])
    assert code == 0
    assert len(out.strip().splitlines()) == 1
    assert len(out.strip()) == 16


def test_cli_count_and_length():
    code, out, _ = run_cli(["-n", "5", "-l", "24"])
    assert code == 0
    lines = out.strip().splitlines()
    assert len(lines) == 5
    assert all(len(line) == 24 for line in lines)


def test_cli_no_symbols():
    code, out, _ = run_cli(["-l", "40", "--no-symbols"])
    assert code == 0
    assert not (set(out.strip()) & set(passgen.SYMBOLS))


def test_cli_json_shape():
    import json
    code, out, _ = run_cli(["-n", "3", "--json"])
    assert code == 0
    data = json.loads(out)
    assert data["kind"] == "password"
    assert len(data["items"]) == 3
    assert data["entropy_bits"] > 0
    assert data["strength"] in ("reasonable", "strong", "very strong")


def test_cli_passphrase_json():
    import json
    code, out, _ = run_cli(["--passphrase", "-w", "5", "--json"])
    assert code == 0
    data = json.loads(out)
    assert data["kind"] == "passphrase"
    assert len(data["items"][0].split("-")) == 5


def test_cli_check_reports_strength():
    import json
    code, out, _ = run_cli(["--check", "abc", "--json"])
    assert code == 0
    data = json.loads(out)
    assert data["password"] == "abc"
    assert data["length"] == 3
    assert data["strength"] == "very weak"
    code, out, _ = run_cli(["--check", "hunter2", "--json"])
    assert code == 0
    data = json.loads(out)
    assert data["strength"] in ("weak", "reasonable")


def test_cli_check_plain_output():
    code, out, _ = run_cli(["--check", "Tr0ub4dor&3"])
    assert code == 0
    assert "entropy:" in out and "strength:" in out


def test_cli_bad_count_rejected():
    code, _, err = run_cli(["-n", "0"])
    assert code == 2
    assert "count" in err


def test_cli_too_short_rejected():
    code, _, err = run_cli(["-l", "2"])
    assert code == 2
    assert "too short" in err


def test_cli_single_class_short_password_ok():
    code, out, _ = run_cli(["-l", "1", "--no-upper", "--no-digits",
                            "--no-symbols"])
    assert code == 0
    assert len(out.strip()) == 1

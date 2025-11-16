# pylint: disable=E0611, R0914, R0915, R0902, R0903, W0718
"""
Application PyQt6 pour générer des mots de passe et analyser leurs faiblesses.
Auteur : Rafael ISTE © 2025
"""

from __future__ import annotations

import math
import re
import shutil
import urllib.request
from pathlib import Path
from typing import Dict, Set, Tuple, Any
from collections import Counter
import random

from PyQt6.QtWidgets import (
    QApplication,
    QWidget,
    QLabel,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QCheckBox,
    QSpinBox,
    QLineEdit,
    QProgressBar,
    QGroupBox,
    QFormLayout,
    QPlainTextEdit,
    QMessageBox,
)
from PyQt6.QtGui import QFont

DATA_DIR = Path("./data")
DATA_DIR.mkdir(exist_ok=True)

REMOTE_SOURCES: Dict[str, str] = {
    "seclists_200": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/2023-200_most_used_passwords.txt", # pylint: disable=C0301
    "seclists_10k": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt", # pylint: disable=C0301
    "english_words": "https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt",
    "french_words": "https://raw.githubusercontent.com/Taknok/French-Wordlist/master/francais.txt",
}
LOCAL_FILES: Dict[str, Path] = {key: DATA_DIR / (key + ".txt") for key in REMOTE_SOURCES}
USER_AGENT = "Mozilla/5.0 (compatible; AdvancedPasswordTool/1.0)"

def download_with_size_check(key: str, url: str, out_path: Path, max_size_mb: int = 200) -> bool:
    """Télécharge un fichier distant si sa taille est raisonnable.

    Args:
        key (str): Clé identifiant la source.
        url (str): URL distante.
        out_path (Path): Chemin de sortie local.
        max_size_mb (int): Taille maximale autorisée en mégaoctets.

    Returns:
        bool: True si téléchargement réussi, False sinon.
    """
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=30) as resp:
            info = resp.info()
            size = info.get("Content-Length")
            if size and int(size) / 1024 / 1024 > max_size_mb:
                return False
            tmp = out_path.with_suffix(".tmp")
            with open(tmp, "wb") as f:
                shutil.copyfileobj(resp, f)
            tmp.rename(out_path)
            return True
    except Exception as e:  # pylint: disable=broad-except
        print(f"[DL] download error {key}: {e}")
        return False


def load_wordset(path: Path, min_len: int = 1, lower: bool = True) -> Set[str]:
    """Charge un fichier de mots et renvoie un ensemble.

    Args:
        path (Path): Chemin vers le fichier.
        min_len (int): Longueur minimale des mots à conserver.
        lower (bool): Mettre en minuscules si True.

    Returns:
        Set[str]: Ensemble de mots.
    """
    s: Set[str] = set()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                w = ln.strip()
                if not w:
                    continue
                if lower:
                    w = w.lower()
                if len(w) >= min_len:
                    s.add(w)
    except Exception as e:
        print(f"[LOAD] error reading {path}: {e}")
    return s

LEET_MAP = str.maketrans("430157", "aeolst")
KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "azertyuiop"]


def pool_size(password: str) -> int:
    """Estime la taille du pool de caractères utilisé par le mot de passe.

    Args:
        password (str): Mot de passe.

    Returns:
        int: Taille estimée du pool.
    """
    ps = 0
    if re.search(r"[a-z]", password):
        ps += 26
    if re.search(r"[A-Z]", password):
        ps += 26
    if re.search(r"[0-9]", password):
        ps += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        ps += 32
    return ps if ps > 0 else 1


def naive_entropy(password: str) -> float:
    """Calcul d'entropie naïf basé sur pool_size et longueur.

    Args:
        password (str): Mot de passe.

    Returns:
        float: Entropie naïve en bits.
    """
    return len(password) * math.log2(pool_size(password))


def is_date_like(password: str) -> bool:
    """Détecte les motifs ressemblant à une date (YYYY, YYYYMMDD, etc.).

    Args:
        password (str): Mot de passe.

    Returns:
        bool: True si ressemble à une date.
    """
    if re.fullmatch(r"\d{4}", password):
        return True
    if re.fullmatch(r"\d{6,8}", password):
        if len(password) == 8:
            try:
                mm = int(password[2:4])
                dd = int(password[4:6])
                if 1 <= mm <= 12 and 1 <= dd <= 31:
                    return True
            except Exception:
                pass
        return True
    return False


def has_keyboard_pattern(password: str) -> bool:
    """Détecte séquences clavier de longueur >= 4 (ex: qwer, 1234).

    Args:
        password (str): Mot de passe.

    Returns:
        bool: True si pattern détecté.
    """
    s = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - 3):
            seq = row[i : i + 4]
            if seq in s or seq[::-1] in s:
                return True
    return False


def has_alpha_sequence(password: str) -> bool:
    """Détecte séquences alphabétiques consécutives (ex: abcd, dcba).

    Args:
        password (str): Mot de passe.

    Returns:
        bool: True si séquence détectée.
    """
    s = password.lower()
    for i in range(len(s) - 3):
        chunk = s[i : i + 4]
        if all(ord(chunk[j + 1]) - ord(chunk[j]) == 1 for j in range(3)):
            return True
        if all(ord(chunk[j]) - ord(chunk[j + 1]) == 1 for j in range(3)):
            return True
    return False


def repetition_penalty(password: str) -> float:
    """Retourne un coefficient multipliant l'entropie selon répétitions.

    Args:
        password (str): Mot de passe.

    Returns:
        float: Coefficient (0.6, 0.8 ou 1.0).
    """
    c = Counter(password)
    most = c.most_common(1)[0][1] if c else 0
    ratio = most / len(password) if password else 0
    if ratio > 0.6:
        return 0.6
    if ratio > 0.4:
        return 0.8
    return 1.0


def pronounceable_score(password: str) -> float:
    """Score simple pour estimer si le mot est prononçable.

    Args:
        password (str): Mot de passe.

    Returns:
        float: Score 0..1.
    """
    vowels = set("aeiouy")
    pw = re.sub(r"[^a-z]", "", password.lower())
    if len(pw) < 3:
        return 0.0
    alt = 0
    for i in range(len(pw) - 1):
        if (pw[i] in vowels) != (pw[i + 1] in vowels):
            alt += 1
    return alt / max(1, (len(pw) - 1))

class WeakLists:
    """Conteneur pour listes faibles (mots communs, dictionnaires)."""

    def __init__(self) -> None:
        """Initialise les ensembles vides."""
        self.common_passwords: Set[str] = set()
        self.dictionary_words: Set[str] = set()

    def load_from_local(self, present: Dict[str, Path]) -> None:
        """Charge les listes locales présentes dans le mapping `present`.

        Args:
            present (Dict[str, Path]): Mapping clef->chemin si le fichier existe.
        """
        for key in ("seclists_200", "seclists_10k"):
            if key in present:
                self.common_passwords |= load_wordset(present[key], min_len=1, lower=True)
        if "english_words" in present:
            self.dictionary_words |= load_wordset(present["english_words"], min_len=3)
        if "french_words" in present:
            self.dictionary_words |= load_wordset(present["french_words"], min_len=3)

    @property
    def sorted_dict_words(self) -> list[str]:
        return sorted(self.dictionary_words, key=len, reverse=True)


def estimate_entropy_realistic(password: str, lists: WeakLists) -> Tuple[float, Dict[str, Any]]:
    """Estime l'entropie réaliste d'un mot de passe et renvoie des notes.

    La fonction combine une entropie naïve et des ajustements basés sur :
    - présence dans listes compromises,
    - mots de dictionnaire (détectés aussi via leet),
    - patterns clavier,
    - séquences alphabétiques,
    - répétitions,
    - prononçabilité.

    Args:
        password (str): Mot de passe à analyser.
        lists (WeakLists): Contient les listes de référence.

    Returns:
        Tuple[float, Dict[str, Any]]: (bits_estimés, info)
    """

    info: Dict[str, Any] = {"password": password, "length": len(password)}

    naive_bits = naive_entropy(password)
    info["naive_bits"] = round(naive_bits, 2)

    pw_low = password.lower()
    if pw_low in lists.common_passwords:
        info["notes"] = "Mot de passe présent dans une liste de mots compromis."
        info["final_bits"] = 4.0
        return 4.0, info

    only_digits = re.fullmatch(r"\d+", password)
    if only_digits:
        is_bad_pattern = is_date_like(password) or has_alpha_sequence(password)
        if is_bad_pattern:
            info["notes"] = "Chiffres seulement — probable date/séquence."
            bits = max(4.0, round(min(20, len(password) * math.log2(10)) * 0.5, 2))
            info["final_bits"] = bits
            return bits, info

    bits_est = naive_bits
    notes = []

    def find_dictionary_hit(pw: str) -> str:
        """Retourne le mot dictionnaire trouvé, sinon ''. """
        for w in lists.sorted_dict_words:
            if w in pw:
                return str(w)
        return ""

    best = find_dictionary_hit(pw_low)

    if not best:
        pw_deleet = pw_low.translate(LEET_MAP)
        best_leet = find_dictionary_hit(pw_deleet)
        if best_leet:
            best = best_leet + " (via leet)"

    if best:
        clean = best.replace(" (via leet)", "")
        random_part = len(clean) * math.log2(26)
        word_entropy = math.log2(50000)
        bits_est = bits_est - random_part + word_entropy
        notes.append(f"Contient mot dictionnaire: {best}")

    if has_keyboard_pattern(password):
        bits_est *= 0.6
        notes.append("Pattern clavier détecté")

    if has_alpha_sequence(password):
        bits_est *= 0.6
        notes.append("Séquence alphabétique détectée")

    rep = repetition_penalty(password)
    if rep < 1.0:
        bits_est *= rep
        notes.append(f"Répétitions détectées (coeff {rep})")

    if pronounceable_score(password) > 0.6 and len(password) >= 6:
        bits_est *= 0.8
        notes.append("Mot prononçable détecté")

    bits_est = max(1.0, bits_est)
    info["notes"] = "; ".join(notes) if notes else ""
    info["final_bits"] = round(bits_est, 2)

    return round(bits_est, 2), info


random_gen = random.SystemRandom()
SYMBOLS = "!@#$%&*?+_-=<>"
AMBIGUOUS = set("Il1O0o")


class GeneratorOptions:
    """Options pour le générateur de mot de passe."""

    def __init__(self) -> None:
        """Initialise les options par défaut."""
        self.length: int = 16
        self.use_lower: bool = True
        self.use_upper: bool = True
        self.use_digits: bool = True
        self.use_symbols: bool = True
        self.exclude_ambiguous: bool = True
        self.pronounceable: bool = False
        self.pattern: str | None = None


class PasswordGenerator:
    """Générateur de mot de passe basé sur GeneratorOptions."""

    def __init__(self, opt: GeneratorOptions) -> None:
        """Initialise le générateur avec les options fournies."""
        self.opt = opt

    def _build_pool(self) -> str:
        """Construit la pool de caractères selon les options."""
        pool = ""
        if self.opt.use_lower:
            pool += "abcdefghijklmnopqrstuvwxyz"
        if self.opt.use_upper:
            pool += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if self.opt.use_digits:
            pool += "0123456789"
        if self.opt.use_symbols:
            pool += SYMBOLS
        if self.opt.exclude_ambiguous:
            pool = "".join(ch for ch in pool if ch not in AMBIGUOUS)
        return pool

    def generate(self) -> str:
        """Génère un mot de passe (ou depuis pattern si fourni)."""
        if self.opt.pattern:
            return self._gen_from_pattern(self.opt.pattern)
        pool = self._build_pool()
        if not pool:
            raise ValueError("Pool vide — sélectionnez des jeux de caractères.")
        return "".join(random_gen.choice(pool) for _ in range(self.opt.length))

    def _gen_from_pattern(self, pattern: str) -> str:
        """Génère depuis un pattern simple (L/l/U/d/D/s/x)."""
        out = ""
        pool = self._build_pool()
        for ch in pattern:
            if ch in "LlU":
                if ch == "L":
                    cand = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                elif ch == "l":
                    cand = "abcdefghijklmnopqrstuvwxyz"
                else:
                    cand = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                if self.opt.exclude_ambiguous:
                    cand = "".join(c for c in cand if c not in AMBIGUOUS)
                out += random_gen.choice(cand)
            elif ch in "dD":
                digits = "0123456789"
                if self.opt.exclude_ambiguous:
                    digits = "".join(c for c in digits if c not in AMBIGUOUS)
                out += random_gen.choice(digits)
            elif ch in "sS":
                out += random_gen.choice(SYMBOLS)
            elif ch == "x":
                out += random_gen.choice(pool)
            else:
                out += ch
        return out

class MainWindow(QWidget):
    """Fenêtre principale PyQt6 du Générateur & Analyseur."""

    def __init__(self) -> None:
        """Initialise la fenêtre et charge les listes locales si présentes."""
        super().__init__()
        self.setWindowTitle("Générateur & Analyse de mots de passe")
        self.setMinimumSize(720, 500)
        self.lists = WeakLists()
        present = {k: p for k, p in LOCAL_FILES.items() if p.exists() and p.stat().st_size > 0}
        self.lists.load_from_local(present)
        self._init_ui()
        self.refresh_ui()

    def _init_ui(self) -> None:
        """Crée et organise les widgets de l'interface."""
        layout = QVBoxLayout()
        title = QLabel("Générateur & Analyse de mots de passe")
        title.setFont(QFont("Segoe UI", 14))
        layout.addWidget(title)

        group_opts = QGroupBox("Options génération")
        form = QFormLayout()
        self.spin_len = QSpinBox()
        self.spin_len.setRange(4, 256)
        self.spin_len.setValue(16)
        self.chk_lower = QCheckBox("Minuscules (a-z)")
        self.chk_lower.setChecked(True)
        self.chk_upper = QCheckBox("Majuscules (A-Z)")
        self.chk_upper.setChecked(True)
        self.chk_digits = QCheckBox("Chiffres (0-9)")
        self.chk_digits.setChecked(True)
        self.chk_symbols = QCheckBox("Symboles")
        self.chk_symbols.setChecked(True)
        self.chk_ambig = QCheckBox("Exclure caractères ambigus (Il1O0o)")
        self.chk_ambig.setChecked(True)
        self.pattern_in = QLineEdit()
        self.pattern_in.setPlaceholderText("Ex: LLL-dd-SS")

        form.addRow("Longueur:", self.spin_len)
        form.addRow(self.chk_lower)
        form.addRow(self.chk_upper)
        form.addRow(self.chk_digits)
        form.addRow(self.chk_symbols)
        form.addRow(self.chk_ambig)
        form.addRow("Motif (optionnel):", self.pattern_in)
        group_opts.setLayout(form)
        layout.addWidget(group_opts)

        gen_box = QGroupBox("Génération")
        vgen = QVBoxLayout()
        self.output_line = QLineEdit()
        self.output_line.setReadOnly(True)
        self.output_line.setFont(QFont("Consolas", 12))
        btns = QHBoxLayout()
        self.btn_gen = QPushButton("Générer")
        self.btn_copy = QPushButton("Copier")
        self.btn_gen.clicked.connect(self.on_generate)
        self.btn_copy.clicked.connect(self.on_copy)
        btns.addWidget(self.btn_gen)
        btns.addWidget(self.btn_copy)
        vgen.addWidget(QLabel("Mot de passe généré:"))
        vgen.addWidget(self.output_line)
        vgen.addLayout(btns)
        gen_box.setLayout(vgen)
        layout.addWidget(gen_box)

        analysis_box = QGroupBox("Analyse & Entropie")
        a_layout = QVBoxLayout()
        self.entropy_bar = QProgressBar()
        self.entropy_bar.setRange(0, 100)
        self.entropy_label = QLabel("Entropie: n/a")
        self.details_text = QPlainTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumBlockCount(1000)
        a_layout.addWidget(self.entropy_bar)
        a_layout.addWidget(self.entropy_label)
        a_layout.addWidget(QLabel("Faiblesses détectées:"))
        a_layout.addWidget(self.details_text)
        analysis_box.setLayout(a_layout)
        layout.addWidget(analysis_box)

        bottom = QHBoxLayout()
        self.input_test = QLineEdit()
        self.input_test.setPlaceholderText("Tester un mot de passe ici...")
        self.btn_test = QPushButton("Tester entropie")
        self.btn_test.clicked.connect(self.on_test)
        bottom.addWidget(self.input_test)
        bottom.addWidget(self.btn_test)
        layout.addLayout(bottom)

        self.setLayout(layout)

    def refresh_ui(self) -> None:
        """Met à jour l'affichage d'entropie et des faiblesses pour le mot généré."""
        pwd = self.output_line.text()
        if pwd:
            bits, info = estimate_entropy_realistic(pwd, self.lists)
            prog, label = self._strength_label(bits)
            self.entropy_bar.setValue(prog)
            self.entropy_label.setText(f"Entropie estimée: {bits} bits — {label}")
            self.details_text.setPlainText(info.get("notes", ""))
        else:
            self.entropy_bar.setValue(0)
            self.entropy_label.setText("Entropie: n/a")
            self.details_text.setPlainText("")

    def _strength_label(self, bits: float) -> Tuple[int, str]:
        """Retourne (progress_value, label) pour une valeur en bits."""
        if bits < 28:
            return 15, "Très faible"
        if bits < 40:
            return 35, "Faible"
        if bits < 60:
            return 55, "Correct"
        if bits < 80:
            return 75, "Fort"
        return 95, "Très fort"

    def on_generate(self) -> None:
        """Génère un mot de passe selon les options de l'UI."""
        opt = GeneratorOptions()
        opt.length = self.spin_len.value()
        opt.use_lower = self.chk_lower.isChecked()
        opt.use_upper = self.chk_upper.isChecked()
        opt.use_digits = self.chk_digits.isChecked()
        opt.use_symbols = self.chk_symbols.isChecked()
        opt.exclude_ambiguous = self.chk_ambig.isChecked()
        pat = self.pattern_in.text().strip()
        opt.pattern = pat if pat else None
        try:
            gen = PasswordGenerator(opt)
            pwd = gen.generate()
            self.output_line.setText(pwd)
            self.refresh_ui()
        except Exception as e:
            QMessageBox.critical(self, "Erreur génération", str(e))

    def on_copy(self) -> None:
        """Copie le mot de passe généré dans le presse-papier."""
        pwd = self.output_line.text()
        if pwd:
            clipboard = QApplication.clipboard()
            if clipboard is not None:
                clipboard.setText(pwd)
                QMessageBox.information(self, "Copié", "Mot de passe copié dans le presse-papier.")

    def on_test(self) -> None:
        """Teste l'entropie d'un mot de passe saisi manuellement."""
        pw = self.input_test.text().strip()
        if not pw:
            return
        bits, info = estimate_entropy_realistic(pw, self.lists)
        prog, label = self._strength_label(bits)
        self.entropy_bar.setValue(prog)
        self.entropy_label.setText(f"Entropie estimée: {bits} bits — {label}")
        self.details_text.setPlainText(info.get("notes", ""))

def main() -> None:
    """Point d'entrée de l'application PyQt6."""
    app = QApplication([])
    w = MainWindow()
    w.show()
    app.exec()


if __name__ == "__main__":
    main()

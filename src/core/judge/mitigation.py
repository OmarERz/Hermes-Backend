"""Validation of the mitigation drafted in `finalize_review` (D-017, docs/07 §13 JUE-MIT-01 to JUE-MIT-06, JUE-MIT-10).

All or nothing (JUE-MIT-05): one failing step discards the whole draft and records the broken rule; the
data-based mitigation (docs/06 §5) is always shown anyway. Length and count limits the strict mode cannot
express are checked here too (VAL-02). A version a step recommends must fall outside every affected range of the
group's product (D-101, JUE-MIT-10). When it opens a floor («X o posterior») and later versions are affected too, the
step passes with a warning the code adds from those ranges (D-106), so nobody upgrades into a vulnerable line.
"""

from __future__ import annotations

import itertools
import logging
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from core.judge.affected import AffectedRange, product_ranges
from core.judge.package import ElementKind, ReviewPackage, SourceLevel, normalize_text
from core.scan.versions import bound_order, known_order, parse_version, wildcard_line

logger = logging.getLogger(__name__)

MAX_STEPS = 20
MAX_ACTION_CHARS = 1000
MIN_QUOTE_CHARS = 12
MAX_QUOTE_CHARS = 1000

# JUE-MIT-03: traceable facts. URLs (with or without scheme, bare hosts), commands in backticks, versions (dotted,
# v-prefixed, or a number after a version word) and file paths must appear in the quote as the same whole fact.
_ADDRESS_CHAR = r"[^\s`'\"<>()]"
# A bracket or typographic quote that opens right before an address closes around it, not inside it.
_CLOSERS = {"[": "]", "{": "}", "\u201c": "\u201d", "\u2018": "\u2019", "\u00ab": "\u00bb"}
_URL = re.compile(rf"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*://{_ADDRESS_CHAR}+")  # any scheme, any case
# Dotted names are read whole, with any port, path or query ('vendor.example.invalid2', never 'vendor.example';
# 'docs.example.org:8443/?id=3', 'docs.example.org/'). Action and quote classify them the same way: a version when
# it is a qualified version below ('3.0.23.post1', 'v3.0.0rc1') or has no two letters in a row ('1.1.1w', 'e.g');
# otherwise a host ('3.0.23.example', '1password.com').
_DOTTED_NAME = rf"(?P<name>(?>[\w+~-]+(?:\.[\w+~-]+)+))(?::\d+)?(?:/{_ADDRESS_CHAR}*|[?#]{_ADDRESS_CHAR}+)?"
_HOST = re.compile(rf"(?<![\w@/.-]){_DOTTED_NAME}")
_LETTERS = re.compile(r"[^\W\d_]{2}")  # 'e.g' and 'U.S.A' are not hosts
_COMMAND = re.compile(r"`([^`\n]+)`")
# A branch (#176) names a release line, not one version: a wildcard ('3.0.x', '3.*') or a dotted number next to a
# branch word ('la rama 3.0', 'the 3.0 branch'). It becomes the fact '3.0.x', where x stands for one or more numbers:
# the quote backs it with one of its versions ('3.0.23', '3.0.11-1~deb12u2'), its wildcard or, for a dotted line,
# the line itself ('3.0'). Any other version token, read whole ('3.0.0-rc1', '1.1.1w', '3.0.x-rc1'), is a version
# fact and has to appear whole in the quote.
_BRANCH_WORD = r"(?:ramas?|series?|l[ií]neas?|branch(?:es)?|lines?)"
_MAJOR_WORD = r"(?:ramas?|series?|branch(?:es)?)"  # 'la rama 4', 'la serie 4'; not 'línea 42' of a file
_NUMBER_END = r"(?![\w+~*-]|\.[\w*])"
_OPEN_QUOTE = r"[\u00ab\u201c\u2018\"']?"  # 'la rama «3.0»'
_CLOSE_QUOTE = r"[\u00bb\u201d\u2019\"']?"
_NAMED_BRANCH = re.compile(
    rf"(?i:\b{_BRANCH_WORD}\s+){_OPEN_QUOTE}[vV]?(\d+(?:\.\d+)+){_NUMBER_END}"
    rf"|(?i:\b{_MAJOR_WORD}\s+){_OPEN_QUOTE}[vV]?(\d+){_NUMBER_END}"
    rf"|(?<![\w.])[vV]?(\d+(?:\.\d+)+){_CLOSE_QUOTE}(?i:\s+{_BRANCH_WORD}\b)"
    rf"|(?<![\w.])[vV]?(\d+){_CLOSE_QUOTE}(?i:\s+(?:rama|serie|branch)\b)"  # 'the 4 branch', not '3 branches'
)
_VERSION = re.compile(r"(?<![\w.])[vV]?(\d+(?:\.(?:\d+|[xX*]))+(?:[0-9A-Za-z_+~*-]|\.(?=[0-9A-Za-z*]))*)")
_WILDCARD = re.compile(r"(\d+(?:\.\d+)*)\.[xX*]")
_VERSION_WORD = re.compile(r"(?i:\b(?:versi[oó]n|version|release|build|v)\s*)(\d+)\b(?!\.\d)")
_PATH = re.compile(r"(?<![\w:/.])(?:~|\.{1,2})?/(?:[\w.-]+/)*[\w.-]+")
_TRAILING = ".,;:"
# A version or branch token in the quote ends where a longer version would go on: '3.0.23' is not in '3.0.23.1',
# '3.0.23-1', '3.0.23+deb', '3.0.23~rc1' or '3.0.23*'. It may carry a 'v' prefix ('v3.0.23').
_VERSION_START = r"(?<![\w./+~-])[vV]?"
_VERSION_END = r"(?![\w/+~*-]|\.[\w*])"
# Version suffixes: '1.1.1w', '-rc1', '+deb12u1', '-1~deb12u2', '-1.el9_2', '.post1', '.Final'.
_SUFFIX = r"(?:[A-Za-z][0-9A-Za-z]*)?+(?:[-+~._][0-9A-Za-z]+)*+"
# URLs and host names in a quote are not versions ('docs.example.org?id=3.0.23', '3.0.23.example'), so version
# evidence is searched without them. A dotted name stays when it is a version: numbered labels and at most one final
# qualifier with a digit or from the usual words that are no domain endings ('3.0.23.post1', '2.4.57-5.el9',
# '2.17.1.redhat-00001', 'v3.0.0rc1', '5.4.24.Final'; not '3.0.23.dev' or '3.0.23.ga').
_QUOTE_NAME = re.compile(rf"(?<![\w/.-]){_DOTTED_NAME}")
# Possessive: a label never gives digits back, so a failing name is rejected in linear time (no ReDoS).
_NUMBERED_LABEL = r"\d++[0-9A-Za-z]*+(?:[-+~_][0-9A-Za-z]++)*+"
_QUALIFIER = (
    r"(?:(?=[0-9A-Za-z+~_-]*\d)[A-Za-z][0-9A-Za-z]*+(?:[-+~_][0-9A-Za-z]++)*+"
    r"|(?i:final|release|alpha|beta|rc|pre|snapshot|lts|stable))"
)
_QUALIFIED_VERSION = re.compile(rf"[vV]?{_NUMBERED_LABEL}(?:\.{_NUMBERED_LABEL})*(?:\.{_QUALIFIER})?")
# Right after an explicit version word, the qualifiers that are also domain endings count: 'version 3.0.23.post'.
_VERSION_CONTEXT = re.compile(r"(?i:\b(?:versi[oó]n|version|release)\s+)$")
_CONTEXT_QUALIFIED = re.compile(rf"[vV]?{_NUMBERED_LABEL}(?:\.{_NUMBERED_LABEL})*\.(?i:post|dev|ga)")
_GAP = "\x00"  # what a read fact leaves behind: no later pattern reads across it ('versión 3.0.23 64-bit')

# D-101 (JUE-MIT-10): the versions an action recommends, read from the words around each version fact within its
# clause (up to '.', ';', '!' or '?'), once URLs, hosts and branches are out. Spanish and English, case ignored. When in
# doubt a version is checked: a wrong check only discards the draft, and the data mitigation is always shown.
# - a target of a move verb ('actualizar', 'migrar', 'pasar', 'subir', 'upgrade', 'update', 'move'...): every version
#   after it whose stretch since the verb or the previous version ends in 'a', 'al', 'hacia', 'to' or 'into' and at most
#   five words that are no version and no 'con', 'desde', 'que', 'y'... ('Actualizar OpenSSL de la rama 3.0 a la versión
#   3.0.23', 'Upgrade hosts running 3.0.22 to OpenSSL 3.0.23', '… a 3.0.24 para la rama 3.0 y a 3.1.22 para la 3.1',
#   'a, como mínimo, la versión 3.0.23'); 'hasta' leads the first target only; once the verb has a target, the end of a
#   set of installed versions is not another one ('Actualizar a 3.0.23 los equipos con 3.0.0 a 3.0.22'), while before
#   it that end is read as where the move goes and checked ('Actualizar los equipos con 3.0.22 a 3.0.23');
#   a bare number counts right after the preposition, an article or a capitalized name ('Actualizar Chrome a 126'),
#   as an install object, as a floor after a product name or a verb of running ('ejecuten 126 o posterior') and as the
#   next item of a list ('to 128 or 126');
# - a replacement after 'reemplazar', 'sustituir', 'cambiar', 'replace' or 'swap' ('por', 'with', 'by' or as above);
# - the object of an install verb ('instalar', 'aplicar', 'desplegar', 'install', 'apply', 'deploy'): the first
#   version after it, at most five words away, after any place ('Instalar OpenSSL 3.0.23', 'Instalar en todos los
#   servidores OpenSSL 3.0.23', `pip install x==1.2.3`, `npm install x@1.2`);
# - a floor ('3.0.23 o posterior', '3.0.23 or later'), unless it describes affected versions ('3.0.0 o posteriores
#   están afectadas', 'affected versions: 3.0.0 and later'; not 'servidores afectados con 3.0.22 o posterior');
# - the version named as the fixed one ('versión corregida: 3.0.23', 'La versión corregida de OpenSSL es 3.0.23',
#   '3.0.23 is the fixed version');
# - the next item of a list after a recommended version ('a 3.0.18, 3.2.6 o 3.5.4', '3.0.23 (rama 3.0) o 3.1.5',
#   '3.0.23 on branch 3.0 or 3.1.22').
# A verb right after a negation ('no', 'nunca', 'evitar', 'do not', 'avoid') recommends nothing, and a version is never
# a recommendation where it is a limit or where a move starts: after 'de la versión', 'desde', 'entre', 'from',
# 'running', 'sin llegar a', 'antes de', 'posterior a', 'below', 'later than', 'not'..., after 'con' or 'with' unless it
# is the replacement, before 'o anterior' /
# 'or earlier', or before 'a'/'to' and another dotted version or a branch ('de 3.0.22 a 3.0.23'; not 'a 3.0.23 a más
# tardar el 1'). Any other version (identification steps, a quoted range) is not checked.
_CLAUSE_BREAK = re.compile(r"[;!?]|\.(?=\s|$)")
_OPENER = "[(\\[«“\"'`]?"  # a bracket, quote or backtick right before a version: '(3.0.18)', '«3.0.18»'
_CLOSER = "[)\\]»”\"'`]?"
_NO_VERSION = rf"(?!{_OPENER}[vV]?\d)"
_STOP = (
    r"(?:con|desde|entre|que|si|sin|en|para|por|sobre|y|e|o|u|from|with|between|than|that|which|if|without|in|on"
    r"|for|and|or|running|ejecutando)"
)
_LEAD_WORD = rf"(?:(?!{_STOP}\b){_NO_VERSION}\S+\s+)"
_ARTICLES = r"(?:(?:la|las|el|los|una?|the|versi[oó]n(?:es)?|versions?|releases?)\s+){0,2}"
_INSTALL = (
    r"(?:re)?instalar\w*|instal(?:e|en|a|an|ando)|aplicar\w*|apli(?:que|quen|ca|can|cando)|desplegar\w*"
    r"|desplieg(?:ue|uen|a|an)|(?:re)?install(?:ing)?|apply(?:ing)?|deploy(?:ing)?"
)
_VERB = re.compile(  # a command flag is no verb (`pip install --upgrade x==1.2`); 'Re-install' still is one
    r"(?<!--)(?<![\s`'\"]-)\b(?:(?P<replace>reempla[zc]\w*|sustitu\w*|cambi(?:ar|e|en|a|an)|replac\w*|swap\w*)"
    r"|(?P<move>actuali[zc]\w*|migr\w*|pas(?:ar|e|en|a|an|ando)|sub(?:ir|a|an|e|en|iendo)|llev(?:ar|e|en|a|an)"
    r"|mov(?:er|e|ed|ing)|upgrad\w*|updat\w*|bump\w*|switch\w*|patch\w*)"
    rf"|(?P<install>{_INSTALL}))\b",
    re.IGNORECASE,
)
_NEGATION = re.compile(r"\b(?:no|nunca|jam[aá]s|evit\w*|never|not|avoid\w*|don't)\s+(?:se\s+)?$", re.IGNORECASE)
_TARGET_LEAD = re.compile(rf"\b(?:a|al|hacia|to|into)(?:\s*,)?\s+{_LEAD_WORD}{{0,5}}{_OPENER}$", re.IGNORECASE)
# 'hasta' leads only the first target of a verb ('Actualizar hasta la versión 3.0.23'; not '… a 3.0.23 (corrige las
# versiones hasta 3.0.22)')
_FIRST_TARGET_LEAD = re.compile(rf"\b(?:hasta)(?:\s*,)?\s+{_LEAD_WORD}{{0,5}}{_OPENER}$", re.IGNORECASE)
_REPLACEMENT_LEAD = re.compile(
    rf"\b(?:a|al|hacia|to|into|por|with|by)(?:\s*,)?\s+{_LEAD_WORD}{{0,5}}{_OPENER}$", re.IGNORECASE
)
_OBJECT_LEAD = re.compile(
    rf"\s+(?:(?:en|on|in)\s+(?:{_NO_VERSION}\S+\s+){{1,4}}?)?"  # a place first: 'Instalar en todos los servidores …'
    rf"(?:(?!(?:a|al|hacia|hasta|to|into)\b){_LEAD_WORD}){{0,5}}(?:['\"]?[\w.-]+(?:==?|>=|@)|{_OPENER})",
    re.IGNORECASE,
)
# a bare number is a version only as a move target or an install object: 'a 126', 'to Chrome 126', 'a la 126',
# 'Instalar Chrome 126', followed by the end of the clause, a mark or a joining word ('a 126 o posterior', 'to 126 on
# every host'); never 'a 3 equipos', 'el 15 de', 'Instalar 2 parches', 'Aplicar el parche 2'
_BARE_NUMBER = re.compile(r"(?<![\w.,:/+~-])\d+(?![\w:/+~*-]|[.,]\d)")
_BARE_LEAD = re.compile(
    rf"\b(?:a|al|to|into|hasta|por|with|by|{_INSTALL})\s+(?:(?:la|el|the)\s+)?(?:(?-i:[A-Z])[\w.+-]*\s+)?{_OPENER}$"
    rf"|\b(?:{_INSTALL})\s+(?:\S+\s+){{0,5}}?['\"]?[\w.-]+(?:==?|>=|@)$",  # `pip install --upgrade x==126`
    re.IGNORECASE,
)
# a bare floor needs a product name or a verb of running or having before it: 'Chrome 126 o posterior', 'ejecuten 126
# o posterior'; never 'nivel 3 o superior'
_BARE_FLOOR_LEAD = re.compile(
    rf"(?:\b(?:ejecut\w*|corr(?:a|an|e|en)|tengan?|sean?|usen?|run\w*|have|has|is|are|be)|(?-i:\b[A-Z])[\w.+-]*)\s+{_OPENER}$",
    re.IGNORECASE,
)
_BARE_REACH = 120  # the lead is a few words long: look no further back
_BARE_TAIL = re.compile(
    rf"{_CLOSER}(?:\s*$|\s*[,;.!?)]|\s+{_STOP}\b|\s+(?:como|al|antes|despu[eé]s|cuanto|tan|lo|de\s+inmediato"
    r"|inmediatamente|ya|ahora|hoy|seg[uú]n|conforme|siguiendo|at|before|after|as|immediately|now|asap|today|per"
    r"|according|following)\b)",
    re.IGNORECASE,
)
# the end of a set of installed versions once the verb has its target: 'Actualizar a 3.0.23 los equipos con 3.0.0 a
# 3.0.22' (before any target it is where the move goes: 'Upgrade hosts running 3.0.22 to 3.0.23')
_SET_END_LEAD = re.compile(
    r"\b(?:con|entre|with|between|running|ejecutando)\s+"
    rf"(?:(?!(?:y|e|o|u|and|or)\b){_NO_VERSION}\S+\s+){{0,4}}{_OPENER}[vV]?\d\S*\s+(?:a|al|hasta|to|through|y|and|-)\s+"
    rf"{_ARTICLES}{_OPENER}$",
    re.IGNORECASE,
)
# 'con' and 'with' name what is installed, except as the replacement ('Replace 3.0.17 with 3.0.18')
# the words between a marker of what is installed and its version never include a target preposition ('Actualizar
# los servidores con OpenSSL a 3.0.22' moves to 3.0.22)
_INSTALLED_WORD = rf"(?:(?!(?:a|al|hacia|hasta|to|into|por|by)\b){_NO_VERSION}\S+\s+)"
_CURRENT_LEAD = re.compile(  # 'with a 3.0.22 release': after 'with', 'a' is an article
    rf"\b(?:con\s+|with\s+(?:(?:a|an|the)\s+)?){_INSTALLED_WORD}{{0,2}}{_OPENER}$", re.IGNORECASE
)
_LIMIT_LEAD = re.compile(
    rf"(?:\b(?:de|del)\s+{_ARTICLES}"
    rf"|\b(?:desde|entre|from|between|running|ejecutando)\s+{_INSTALLED_WORD}{{0,2}}"
    # an installed limit: 'running up to 3.0.22', 'con versiones hasta 3.0.22'
    rf"|\b(?:running|ejecutando|with|con)\s+{_INSTALLED_WORD}{{0,2}}(?:up\s+to|hasta)\s+{_ARTICLES}"
    r"|\b(?:sin\s+llegar\s+a|sin\s+pasar\s+(?:a|de)|antes\s+de|por\s+(?:debajo|encima)\s+de"
    r"|(?<!\bo )(?<!\bu )(?<!\bor )(?:anterior|inferior|posterior|superior)(?:es)?\s+a"
    r"|(?:menor|mayor)(?:es)?\s+(?:a|que)|distint[ao]s?\s+(?:a|de)"
    r"|en\s+(?:lugar|vez)\s+de|excepto|salvo|below|before|after|above|prior\s+to"
    r"|(?:earlier|lower|less|older|later|newer|greater|higher|other)\s+than|without\s+reaching|instead\s+of|except"
    rf"|not)\s+{_ARTICLES}){_OPENER}$",
    re.IGNORECASE,
)
_MOVE_START_TAIL = re.compile(
    rf"{_CLOSER}\s+(?:a|al|hacia|hasta|to|into)\s+{_LEAD_WORD}{{0,5}}(?:{_OPENER}[vV]?\d+\.\d|{_GAP})", re.IGNORECASE
)
_LOWER_TAIL = re.compile(
    rf"{_CLOSER}\s*,?\s*(?:o|u|or|y|and)\s+(?:anterior|inferior|previa|menor|earlier|lower|older|below|prior)",
    re.IGNORECASE,
)
# a floor, also one that names the noun («3.0.23 o una versión posterior», «3.0.23 or a later version», F15.9)
_FLOOR_TAIL = re.compile(
    rf"{_CLOSER}\s*,?\s*(?:(?:o|u|or|y|and)\s+(?:una\s+|a\s+|any\s+)?(?:(?:posterior|superior|mayor)(?:es)?"
    r"|m[aá]s\s+recientes?|later|higher|newer|above|greater)\b|en\s+adelante|onwards?"
    r"|(?:o|u|or)\s+(?:una\s+|a\s+|any\s+)?(?:versi[oó]n(?:es)?|versions?|releases?)\s+"
    r"(?:(?:posterior|superior|mayor)(?:es)?|m[aá]s\s+recientes?)\b"
    r"|(?:o|or)\s+(?:una\s+|a\s+|any\s+)?(?:later|higher|newer)\s+(?:versions?|releases?)\b)",
    re.IGNORECASE,
)
# a floor of affected versions: it is the subject of 'están afectadas' / 'are affected' right after it ('3.0.0 o
# posteriores están afectadas'; not 'run 3.0.22 or later, as earlier versions are affected'), or comes right after
# 'versiones afectadas:' / 'affected versions are' ('… is deployed to affected hosts' and 'Revisar las versiones
# afectadas y comprobar que los equipos ejecuten 3.0.22 o posterior' are still floors)
_AFFECTED = re.compile(  # the subject may end in its noun: '3.0.0 and later versions are affected'
    r"(?:\s+(?:versi[oó]n(?:es)?|versions?|releases?|builds?)(?:\s+(?:of|de|del|for|para|on|in|en)(?:\s+[^\s,;]+){1,3}?)?)?"
    r"\s+(?:est[aá]n?|son|es|siguen?|quedan?|are|is|were|was"
    r"|remains?)\s+(?:(?:also|still|todav[ií]a|a[uú]n|tambi[eé]n)\s+)?"
    r"(?:afectad\w*|vulnerables?|affected|impacted)\b",
    re.IGNORECASE,
)
_AFFECTED_VERSIONS = re.compile(
    r"\b(?:(?:versi[oó]n(?:es)?|versions?|releases?)\s+(?:afectad\w*|vulnerables?|affected|impacted)"
    r"|(?:affected|vulnerable|impacted)\s+(?:versions?|releases?))"
    rf"(?:\s+(?:de|del|of|for|para)(?:\s+(?!{_STOP}(?:\s|$))[^\s,;]+){{1,3}}?)?"
    rf"\s*(?::|\s(?:son|es|incluyen|are|is|include)\b)?\s*{_ARTICLES}{_OPENER}$",
    re.IGNORECASE,
)
_FIXED_LEAD = re.compile(
    r"\b(?:versi[oó]n(?:es)?\s+(?:corregidas?|parcheadas?|seguras?|recomendadas?|m[ií]nimas?)"
    r"|(?:fixed|patched|safe|recommended|minimum)\s+(?:versions?|releases?))"
    rf"(?:\s+(?:de|del|para|of|for)(?:\s+(?!{_STOP}(?:\s|$))[^\s,;]+){{1,3}}?)?\s*(?::|\s(?:es|son|is|are)\b)?\s*(?:la\s+|the\s+)?"
    rf"{_OPENER}$",
    re.IGNORECASE,
)
# between the items of a list: a bracketed note or a short note after 'on', 'in', 'for', 'para' or 'en' ('3.0.23 on
# branch 3.0 or 3.1.22', 'a 3.0.18 en los servidores web y 3.2.6')
# the version as the subject: '3.0.22 is the fixed version', '3.0.23 es la primera versión corregida'
_FIXED_TAIL = re.compile(
    rf"{_CLOSER}\s+(?:is|es|ser[aá]|will\s+be)\s+(?:the|la)\s+(?:(?:first|primera|latest|[uú]ltima)\s+)?"
    r"(?:(?:fixed|patched|safe|recommended|minimum)\s+(?:version|release)"
    r"|versi[oó]n\s+(?:corregida|parcheada|segura|recomendada|m[ií]nima))",
    re.IGNORECASE,
)
_LIST_GAP = re.compile(
    rf"{_CLOSER}\s*(?:\([^()]{{0,80}}\)\s*)?(?:(?:on|in|for|para|en)(?:\s+{_NO_VERSION}[^\s,;()]+){{1,4}}\s*)?,?\s*\(?\s*(?:(?:o|u|y|e|or|and)\s+)?(?:(?:a|al|to)\s+)?(?:(?:la|the)\s+)?"
    rf"(?:(?:versi[oó]n|version)\s+)?{_OPENER}",
    re.IGNORECASE,
)


class FactKind(StrEnum):
    URL = "url"
    COMMAND = "command"
    HOST = "host"
    BRANCH = "branch"
    VERSION = "version"
    PATH = "path"


@dataclass(frozen=True)
class TraceableFact:
    """A fact written in an action that its quote must back (JUE-MIT-03). A branch is written '3.0.x'. A version the
    action recommends upgrading or moving to is `recommended` (D-101, JUE-MIT-10)."""

    kind: FactKind
    text: str
    recommended: bool = False
    floor: bool = False  # a recommended version followed by «o posterior» / «or later» (D-106)

    def in_quote(self, quote: str) -> bool:
        if self.kind is FactKind.BRANCH:
            # A whole token: one version of the line, with any suffix ('3.0.23', '3.0.23.1', '3.0.11-1~deb12u2',
            # '1.1.1w' for 1.1.x), its bare wildcard ('3.0.x') or the dotted line itself ('3.0', '3.0-rc1'); never
            # '13.0.1', '3.01', '3.0.x-rc1', a host name ('3.0.23.support.example') or, for the 3.x line, a bare '3'.
            # Atomic: no backtracking to a prefix.
            line = self.text.removesuffix(".x")
            itself = r"|(?:[-+~_][0-9A-Za-z]+)*+" if "." in line else ""
            tail = rf"(?>(?:\.\d+)++{_SUFFIX}|\.[xX*]{itself})"
            pattern = rf"{_VERSION_START}{re.escape(line)}{tail}{_VERSION_END}"
            return re.search(pattern, _without_hosts(quote)) is not None
        if self.kind is FactKind.VERSION:
            pattern = rf"{_VERSION_START}{re.escape(self.text)}{_VERSION_END}"
            return re.search(pattern, _without_hosts(quote)) is not None
        # Addresses are compared whole, as the same pattern reads them on both sides: 'docs.example.org/' is not
        # backed by 'docs.example.org/?x=1', nor 'https://a.example/x' by 'https://a.example/x?y=1'.
        if self.kind is FactKind.HOST:
            return any(_is_address(match) and _address(match) == self.text for match in _QUOTE_NAME.finditer(quote))
        if self.kind is FactKind.URL:
            return any(_address(match) == self.text for match in _URL.finditer(quote))
        return appears_as_fact(self.text, quote)


def _is_address(match: re.Match[str]) -> bool:
    """Whether a dotted name is an address rather than a version, by the same rule in the action and the quote."""
    address, name = match.group(0), match.group("name")
    if address != name:  # with a port, path or query it is an address ('1.2.3.4:8443/?id=3.0.23')
        return True
    if _LETTERS.search(name) is None or _QUALIFIED_VERSION.fullmatch(name) is not None:
        return False
    explicit = _VERSION_CONTEXT.search(match.string, 0, match.start()) is not None
    return not (explicit and _CONTEXT_QUALIFIED.fullmatch(name))


def _without_hosts(quote: str) -> str:
    return _QUOTE_NAME.sub(lambda match: _GAP if _is_address(match) else match.group(0), _URL.sub(_GAP, quote))


class MitigationStatus(StrEnum):
    ACCEPTED = "accepted"
    DISCARDED = "discarded"
    ABSENT = "absent"


@dataclass(frozen=True)
class MitigationStep:
    order: int
    ci_id: str | None  # None: applies to every CI of the group
    action: str
    element_id: str
    quote: str


@dataclass(frozen=True)
class MitigationResult:
    status: MitigationStatus
    steps: tuple[MitigationStep, ...] = ()
    rule: str | None = None  # JUE-MIT-xx or VAL-02 when discarded

    @classmethod
    def absent(cls) -> MitigationResult:
        return cls(MitigationStatus.ABSENT)


class _DiscardError(Exception):
    """Internal control flow: one failing step discards the draft. Never escapes this module."""

    def __init__(self, rule: str) -> None:
        super().__init__(rule)
        self.rule = rule


def validate_mitigation(raw_steps: Sequence[Mapping[str, Any]], package: ReviewPackage) -> MitigationResult:
    if not raw_steps:
        return MitigationResult.absent()
    ranges = product_ranges(package)
    try:
        steps = tuple(_step(raw, package, ranges) for raw in raw_steps)
        _check_order(steps)
    except _DiscardError as discard:
        return MitigationResult(MitigationStatus.DISCARDED, rule=discard.rule)
    return MitigationResult(MitigationStatus.ACCEPTED, steps=tuple(sorted(steps, key=lambda s: s.order)))


def _step(raw: Mapping[str, Any], package: ReviewPackage, ranges: Sequence[AffectedRange]) -> MitigationStep:
    action = str(raw["action"]).strip()
    quote = normalize_text(str(raw["quote"]))
    if not action or len(action) > MAX_ACTION_CHARS or len(quote) > MAX_QUOTE_CHARS:
        raise _DiscardError("VAL-02")
    element = package.elements.get(str(raw["element_id"]))
    if element is None or element.kind is ElementKind.CI or element.suspicious:  # SEG-03: never from a suspect
        raise _DiscardError("JUE-MIT-01")
    if len(quote) < MIN_QUOTE_CHARS or not element.contains(quote):
        raise _DiscardError("JUE-MIT-02")
    # JUE-MIT-01: only N1 data. In the CVE element, analyst output (conditions, components, inferred CVSS) is N4;
    # a news item counts only if its source is N1 (vendor advisory).
    if element.quote_level(quote) is not SourceLevel.N1:
        raise _DiscardError("JUE-MIT-01")
    facts = traceable_facts(action)
    if not all(fact.in_quote(quote) for fact in facts):
        raise _DiscardError("JUE-MIT-03")
    if not all(_outside(fact.text, ranges, package.group_cve) for fact in facts if fact.recommended):
        raise _DiscardError("JUE-MIT-10")
    ci_id = str(raw["ci_id"]).strip()
    if ci_id and ci_id not in package.ci_ids:
        raise _DiscardError("JUE-MIT-04")
    warning = later_versions_warning([fact.text for fact in facts if fact.floor], ranges)
    return MitigationStep(
        order=int(raw["order"]),
        ci_id=ci_id or None,
        action=_with_warning(action, warning),
        element_id=element.element_id,
        quote=quote,
    )


def _with_warning(action: str, warning: str | None) -> str:
    if not warning:
        return action
    return f"{action} {warning}" if action.endswith((".", "!", "?", ";", ":")) else f"{action}. {warning}"


MAX_WARNED_RANGES = 8
WARNING_LEAD = "Advertencia de Hermes: versiones posteriores también afectadas: "


def later_versions_warning(floors: Sequence[str], ranges: Sequence[AffectedRange]) -> str | None:
    """D-106: the affected ranges of the product that lie after a recommended floor («1.5 o posterior» with [2.0,)),
    in Spanish and taken from the data; None when there are none. Only ranges known to hold a later version count."""
    later: dict[tuple[str | None, bool, str | None, bool], AffectedRange] = {}
    for affected in sorted((r for version in floors for r in ranges if _after(version, r)), key=_start_key):
        # NVD and the CNA can publish the same interval under their own names: it is said once
        later.setdefault((affected.start, affected.start_inclusive, affected.end, affected.end_inclusive), affected)
    if not later:
        return None
    ordered = list(later.values())
    shown = "; ".join(_describe(r) for r in ordered[:MAX_WARNED_RANGES])
    more = len(ordered) - MAX_WARNED_RANGES
    return f"{WARNING_LEAD}{shown}{f'; y {more} más' if more > 0 else ''}."


def _after(version: str, affected: AffectedRange) -> bool:
    """The range lies after `version` (which JUE-MIT-10 already placed outside it): the version comes before its start.
    A range open at the start cannot lie after it; a start the comparator cannot place gives no warning."""
    if not affected.readable or affected.start is None:
        return False
    order = bound_order(version, affected.start, known_order)
    return order is not None and (order < 0 or (order == 0 and not affected.start_inclusive))


def _start_key(affected: AffectedRange) -> tuple[bool, Any, str]:
    start = affected.start
    line = wildcard_line(start) if start is not None else None
    parsed = parse_version(".".join(map(str, line)) if line is not None else start) if start is not None else None
    return (parsed is None, parsed or (), affected.text)


def _bound(text: str) -> str:
    line = wildcard_line(text)
    return f"la línea {'.'.join(map(str, line))}" if line is not None else text


def _describe(affected: AffectedRange) -> str:
    """`[3.2.0,3.2.6)` → «de 3.2.0 a antes de 3.2.6»; `[2.0,)` → «desde 2.0»; `(6.1.*,6.6.162)` → «después de la línea
    6.1 y antes de 6.6.162»."""
    start, end = str(affected.start), affected.end  # a later range always has a start (`_after`)
    if affected.start_inclusive:
        head = f"desde {_bound(start)}" if end is None else f"de {_bound(start)}"
    else:
        head = f"después de {_bound(start)}"
    if end is None:
        return head
    if affected.start_inclusive and affected.end_inclusive:
        return f"{head} a {_bound(end)}"  # «de 128 a 130»
    tail = f"hasta {_bound(end)}" if affected.end_inclusive else f"antes de {_bound(end)}"
    joiner = " a " if affected.start_inclusive else " y "
    return f"{head}{joiner}{tail}"


def _outside(version: str, ranges: Sequence[AffectedRange], cve: str | None) -> bool:
    """D-101: the recommended version lies outside every affected range of the product. A range the comparator cannot
    place it against counts as not outside: the draft is discarded and the comparison error logged (ESC-13)."""
    for affected in ranges:
        inside = affected.contains(version)
        if inside is None:
            logger.warning(
                "JUE-MIT-10: %s cannot be compared with the affected range %r of %s; the draft is discarded",
                repr(version),
                affected.text,
                repr(cve),
            )
        if inside is not False:
            return False
    return True


def _check_order(steps: Sequence[MitigationStep]) -> None:
    if len(steps) > MAX_STEPS:
        raise _DiscardError("VAL-02")
    if sorted(step.order for step in steps) != list(range(1, len(steps) + 1)):
        raise _DiscardError("JUE-MIT-06")


def appears_as_fact(fact: str, quote: str) -> bool:
    """The same whole fact is in the quote: '2.4.6' does not match '2.4.60', nor a URL a longer URL."""
    pattern = rf"(?<![\w./-]){re.escape(fact)}(?![\w/-]|\.\w)"
    return re.search(pattern, quote) is not None


def traceable_facts(action: str) -> list[TraceableFact]:
    """Versions, branches, URLs, backticked commands and file paths written in an action (JUE-MIT-03)."""
    text = normalize_text(action)
    facts = _facts(FactKind.URL, (_address(match) for match in _URL.finditer(text)))
    facts += _facts(FactKind.COMMAND, (normalize_text(command) for command in _COMMAND.findall(text)))
    without_urls = _URL.sub(" ", text)
    hosts, without_hosts = _split_hosts(without_urls)
    facts += _facts(FactKind.HOST, hosts)
    named = (next(number for number in groups if number) for groups in _NAMED_BRANCH.findall(without_hosts))
    facts += _facts(FactKind.BRANCH, (f"{number}.x" for number in named))
    without_branches = _NAMED_BRANCH.sub(_GAP, without_hosts)
    tokens = list(_VERSION.finditer(without_branches))
    # what is read becomes a run of gaps of its length, so the next patterns keep the positions of the text
    masked = _blank(without_branches, (match.span() for match in tokens))
    numbers = list(_VERSION_WORD.finditer(masked))
    masked = _blank(masked, (match.span(1) for match in numbers))
    spans = [match.span() for match in tokens] + [match.span(1) for match in numbers]
    bare = _bare_numbers(without_branches, masked, spans)
    targets = _recommended(without_branches, spans + bare)

    def floor(end: int) -> bool:
        return _FLOOR_TAIL.match(without_branches, end) is not None

    facts += [_version_fact(match.group(1), match.span() in targets, floor=floor(match.end())) for match in tokens]
    facts += [
        TraceableFact(
            FactKind.VERSION, match.group(1), match.span(1) in targets, floor(match.end(1)) and match.span(1) in targets
        )
        for match in numbers
    ]
    facts += [
        TraceableFact(FactKind.VERSION, without_branches[a:b], True, floor(b)) for a, b in bare if (a, b) in targets
    ]
    facts += _facts(FactKind.PATH, (path.rstrip(_TRAILING) for path in _PATH.findall(without_hosts)))
    return facts


def _bare_numbers(text: str, masked: str, spans: Sequence[tuple[int, int]]) -> list[tuple[int, int]]:
    """The bare numbers that may be a recommended version: a move target, a replacement or an install object ('a 126',
    'hasta 126', 'por 126', 'Instalar Chrome 126'), a floor ('126 o posterior'), the fixed version ('La versión
    corregida es 126') or the next item of a list after a version ('to 128 or 126')."""
    found: list[tuple[int, int]] = []
    for match in _BARE_NUMBER.finditer(masked):
        start, end = match.span()
        if _FIXED_TAIL.match(text, end):  # '126 is the fixed version'
            found.append((start, end))
            continue
        if not _BARE_TAIL.match(text, end):
            continue
        before = [span for span in (*spans, *found) if span[1] <= start]
        listed = bool(before) and _LIST_GAP.fullmatch(text, max(before, key=_end)[1], start) is not None
        lead = _BARE_LEAD.search(text, max(0, start - _BARE_REACH), start) is not None
        floor = _FLOOR_TAIL.match(text, end) and _BARE_FLOOR_LEAD.search(text, max(0, start - _BARE_REACH), start)
        fixed = _FIXED_LEAD.search(text, max(0, start - _BARE_REACH), start)
        if lead or listed or floor or fixed:
            found.append((start, end))
    return found


def _end(span: tuple[int, int]) -> int:
    return span[1]


def _blank(text: str, spans: Iterable[tuple[int, int]]) -> str:
    chars = list(text)
    for start, end in spans:
        chars[start:end] = _GAP * (end - start)
    return "".join(chars)


def _recommended(text: str, spans: Sequence[tuple[int, int]]) -> set[tuple[int, int]]:
    """The spans of the versions the action recommends (D-101); the rules are above `_CLAUSE_BREAK`."""
    targets: set[tuple[int, int]] = set()
    bounds = [0, *(cut for match in _CLAUSE_BREAK.finditer(text) for cut in match.span()), len(text)]
    for start, end in zip(bounds[::2], bounds[1::2], strict=True):
        clause = sorted(span for span in spans if start <= span[0] and span[1] <= end)
        limits = {span for span in clause if _is_limit(text, span, start, end)}
        current = {span for span in clause if _CURRENT_LEAD.search(text, start, span[0])}
        candidates = [span for span in clause if span not in limits and span not in current]
        verbs = list(_VERB.finditer(text, start, end))
        for index, verb in enumerate(verbs):
            stop = verbs[index + 1].start() if index + 1 < len(verbs) else end
            if _NEGATION.search(text, start, verb.start()):
                continue
            if verb.lastgroup == "install":  # its object: the first version, with no other version before it
                first = next((span for span in clause if verb.end() <= span[0] < stop), None)
                if first in candidates and _OBJECT_LEAD.fullmatch(text, verb.end(), first[0]):
                    targets.add(first)
                continue
            replaces = verb.lastgroup == "replace"
            lead = _REPLACEMENT_LEAD if replaces else _TARGET_LEAD
            previous_end, has_target = verb.end(), False
            for span in (span for span in clause if verb.end() <= span[0] < stop):
                allowed = span in candidates or (replaces and span not in limits)
                if has_target and _SET_END_LEAD.search(text, start, span[0]):
                    allowed = False
                up_to = not has_target and _FIRST_TARGET_LEAD.search(text, previous_end, span[0]) is not None
                if allowed and (up_to or lead.search(text, previous_end, span[0])):
                    targets.add(span)
                    has_target = True
                previous_end = span[1]
        for span in candidates:
            tail = _FLOOR_TAIL.match(text, span[1], end)
            subject = tail is not None and _AFFECTED.match(text, tail.end(), end) is not None
            floor = tail is not None and not subject and _AFFECTED_VERSIONS.search(text, start, span[0]) is None
            if floor or _FIXED_LEAD.search(text, start, span[0]) or _FIXED_TAIL.match(text, span[1], end):
                targets.add(span)
        for previous, span in itertools.pairwise(clause):  # a list after a recommended version
            if previous in targets and span in candidates and _LIST_GAP.fullmatch(text, previous[1], span[0]):
                targets.add(span)
    return targets


def _is_limit(text: str, span: tuple[int, int], start: int, end: int) -> bool:
    """A version that is a limit or where a move starts, never a recommendation (D-101)."""
    return bool(
        _LIMIT_LEAD.search(text, start, span[0])
        or _LOWER_TAIL.match(text, span[1], end)
        or _MOVE_START_TAIL.match(text, span[1], end)
    )


def _address(match: re.Match[str]) -> str:
    """The address a match read, without the punctuation that ends the sentence and without the closing mark of a
    bracket or quote opened right before it: '[https://vendor.example/advisory]' and '“https://…”' lose it, while
    'https://[2001:db8::1234]', 'docs.example.org/advisory]' and a typographic apostrophe inside a path keep theirs."""
    address = match.group(0).rstrip(_TRAILING)
    opener = match.string[match.start() - 1] if match.start() else ""
    closer = _CLOSERS.get(opener)
    if closer and address.endswith(closer) and (closer not in "]}" or address.count(closer) > address.count(opener)):
        address = address[: -len(closer)].rstrip(_TRAILING)
    return address


def _split_hosts(text: str) -> tuple[list[str], str]:
    """The host names of an action, each read whole, and the text without them."""
    hosts: list[str] = []

    def take(match: re.Match[str]) -> str:
        if not _is_address(match):
            return match.group(0)
        hosts.append(_address(match))
        return " "

    return hosts, _HOST.sub(take, text)


def _version_fact(token: str, recommended: bool, *, floor: bool = False) -> TraceableFact:
    """A version token read whole: a bare wildcard is a branch ('3.0.X' -> '3.0.x'), anything else a version."""
    wildcard = _WILDCARD.fullmatch(token)
    if wildcard is not None:
        return TraceableFact(FactKind.BRANCH, f"{wildcard.group(1)}.x")
    return TraceableFact(FactKind.VERSION, token, recommended, recommended and floor)


def _facts(kind: FactKind, texts: Iterable[str]) -> list[TraceableFact]:
    return [TraceableFact(kind, text) for text in texts if text]

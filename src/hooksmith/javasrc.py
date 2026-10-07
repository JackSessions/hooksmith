"""A deliberately small Java source reader for jadx output.

jadx emits very regular code, so brace matching plus a few regexes is enough to find methods,
spot `native` declarations and harvest static constants. It is not a Java parser and does not try
to be one. When it cannot tell, callers mark the finding UNVALIDATED instead of guessing.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

_MODS = r"(?:public|protected|private|static|final|abstract|synchronized|native|strictfp|default)"
_METHOD_RE = re.compile(
    rf"^[ \t]*((?:{_MODS}\s+)*)"  # modifiers
    r"(?:<[^>\n]+>\s+)?"  # generic type params
    r"([\w\.\[\]<>?,\s]+?)\s+"  # return type
    r"(\w+)\s*\(([^)]*)\)"  # name(params)
    r"\s*(?:throws\s+[\w\.,\s]+)?\s*(\{|;)",  # body or abstract/native ;
    re.M,
)
_CTOR_NAMES = {"$init"}
_NOT_METHODS = {"if", "for", "while", "switch", "catch", "return", "new", "else", "try", "synchronized"}
_MOD_WORDS = set(_MODS.strip("(?:)").split("|"))


@dataclass
class JavaMethod:
    name: str
    params: list[str]  # type names as written, e.g. ["byte[]", "java.lang.String"]
    modifiers: set[str]
    start: int  # offset of the declaration
    end: int  # offset just after the closing brace (or ';')
    body: str

    @property
    def is_native(self) -> bool:
        return "native" in self.modifiers

    @property
    def is_abstract(self) -> bool:
        return "abstract" in self.modifiers


@dataclass
class JavaClass:
    name: str
    source: str
    methods: list[JavaMethod] = field(default_factory=list)

    def find(self, name: str, arity: int | None = None) -> list[JavaMethod]:
        name = "<init>" if name in _CTOR_NAMES else name
        out = [m for m in self.methods if m.name == name]
        if arity is not None:
            narrowed = [m for m in out if len(m.params) == arity]
            out = narrowed or out
        return out


def _match_brace(src: str, open_idx: int) -> int:
    """Index just after the brace that closes the one at open_idx. Skips strings and comments."""
    depth, i, n = 0, open_idx, len(src)
    while i < n:
        c = src[i]
        if c == "/" and src.startswith("//", i):
            i = src.find("\n", i)
            i = n if i == -1 else i
            continue
        if c == "/" and src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j == -1 else j + 2
            continue
        if c in "\"'":
            q = c
            i += 1
            while i < n and src[i] != q:
                i += 2 if src[i] == "\\" else 1
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def _split_params(raw: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in raw:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    types = []
    for p in out:
        toks = re.sub(r"\bfinal\b|@\w+(\([^)]*\))?", "", p).split()
        if len(toks) >= 2:
            toks = toks[:-1]  # drop the parameter name
        types.append(" ".join(toks))
    return types


def parse_class(name: str, source: str) -> JavaClass:
    methods: list[JavaMethod] = []
    simple = name.split(".")[-1].split("$")[-1]
    for m in _METHOD_RE.finditer(source):
        mods, _ret, mname, params, term = m.groups()
        if mname in _NOT_METHODS:
            continue
        if mname == simple and _ret.strip() in _MOD_WORDS:
            # A true constructor has no return type, so the regex's "return type" slot ends up holding a
            # modifier instead (see the regex comment above). A regular method can legally share its name
            # with the enclosing class too (e.g. `class a { static byte[] a(...) {...} }`, seen in a real
            # obfuscated app) -- that one DOES have a real return type, so _ret won't be a modifier word,
            # and it must keep its real name rather than being folded into the constructor.
            mname = "<init>"  # constructors: Frida calls this $init
        mods_set = set(mods.split())
        decl_start = m.start()
        end = _match_brace(source, m.end() - 1) if term == "{" else m.end()
        methods.append(
            JavaMethod(
                name=mname,
                params=_split_params(params),
                modifiers=mods_set,
                start=decl_start,
                end=end,
                body=source[decl_start:end],
            )
        )
    # drop matches that sit inside another method body (calls like `foo(x) {` never occur in jadx
    # output, but anonymous classes and lambdas can produce nested "methods")
    return JavaClass(name=name, source=source, methods=methods)


def class_to_path(class_name: str) -> str:
    """com.a.B$C -> com/a/B.java (inner classes live in their outer class's file)."""
    outer = class_name.split("$", 1)[0]
    return outer.replace(".", "/") + ".java"


# ---- static constants -------------------------------------------------------------------------

_STR_RE = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
_BYTES_RE = re.compile(r"new\s+byte\s*\[\s*\]\s*\{([^}]*)\}")
_INT_RE = re.compile(r"-?(?:0x[0-9a-fA-F]+|\d+)")


def static_constants(source: str) -> dict[str, list[bytes]]:
    """Candidate key material present as constants in the source, keyed by how it was found."""
    found: dict[str, list[bytes]] = {"string": [], "base64": [], "hex": [], "bytes": []}
    for lit in _STR_RE.findall(source):
        try:
            raw = bytes(lit, "utf-8").decode("unicode_escape").encode("latin-1", "ignore")
        except Exception:  # noqa: BLE001
            raw = lit.encode()
        if raw:
            found["string"].append(raw)
        if len(lit) >= 16 and re.fullmatch(r"[A-Za-z0-9+/=]+", lit):
            try:
                found["base64"].append(base64.b64decode(lit + "=" * (-len(lit) % 4), validate=True))
            except (binascii.Error, ValueError):
                pass
        if len(lit) >= 32 and len(lit) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", lit):
            found["hex"].append(bytes.fromhex(lit))
    for body in _BYTES_RE.findall(source):
        try:
            vals = [int(t, 0) & 0xFF for t in _INT_RE.findall(body)]
        except ValueError:
            continue
        if vals:
            found["bytes"].append(bytes(vals))
    return found


def key_constants(source: str, sizes: tuple[int, ...] = (16, 24, 32)) -> list[tuple[str, bytes]]:
    """(origin, bytes) for every constant whose length is a valid AES-style key size."""
    out = []
    for origin, vals in static_constants(source).items():
        for v in vals:
            if len(v) in sizes:
                out.append((origin, v))
    return out


def obfuscation_score(class_name: str, source: str) -> float:
    """0..1. R8/ProGuard renames *declarations* (classes, packages, members) to a, b, c...; locals are
    short in normal code too, so only declared names count."""
    parts = class_name.replace("$", ".").split(".")
    simple, pkg = parts[-1], parts[:-1]
    jc = parse_class(class_name, source)
    names = [m.name for m in jc.methods if m.name != "<init>"]
    short = lambda n: len(n) <= 2 or bool(re.fullmatch(r"[a-z]\d+[a-z]*", n))  # noqa: E731
    method_frac = sum(short(n) for n in names) / len(names) if names else 0.0
    pkg_frac = sum(short(p) for p in pkg) / len(pkg) if pkg else 0.0
    class_short = 1.0 if short(simple) else 0.0
    return round((method_frac + pkg_frac + class_short) / 3 + (0.1 if method_frac > 0.8 and class_short else 0.0), 2)


# ---- Frida overload descriptors ---------------------------------------------------------------

_PRIM_ARRAY = {"byte": "B", "int": "I", "long": "J", "short": "S", "char": "C", "boolean": "Z", "float": "F", "double": "D"}
_JAVA_LANG = {
    "String",
    "Object",
    "Integer",
    "Long",
    "Boolean",
    "Byte",
    "Short",
    "Character",
    "Float",
    "Double",
    "CharSequence",
    "StringBuilder",
    "StringBuffer",
    "Number",
    "Class",
    "Exception",
    "Throwable",
}
_PRIMITIVES = set(_PRIM_ARRAY) | {"void"}


def imports(source: str) -> dict[str, str]:
    """simple name -> fully qualified name, from `import a.b.C;` lines."""
    return {m.group(2): m.group(1) + m.group(2) for m in re.finditer(r"^import\s+([\w\.]+?\.)(\w+);", source, re.M)}


def frida_type(java_type: str, imp: dict[str, str]) -> str | None:
    """Convert a Java type as written in source to the string Frida's overload() wants, or None."""
    t = re.sub(r"<.*>", "", java_type).strip().replace("final ", "")
    dims = t.count("[]")
    base = t.replace("[]", "").strip()
    if base in _PRIMITIVES:
        return base if not dims else "[" * dims + _PRIM_ARRAY[base]
    if "." in base:
        fq = base
    elif base in imp:
        fq = imp[base]
    elif base in _JAVA_LANG:
        fq = f"java.lang.{base}"
    else:
        return None
    return fq if not dims else "[" * dims + f"L{fq};"


def overload_types(method: JavaMethod, source: str) -> list[str] | None:
    imp = imports(source)
    out = []
    for p in method.params:
        ft = frida_type(p, imp)
        if ft is None:
            return None
        out.append(ft)
    return out


# ---- choosing the method to hook ----------------------------------------------------------------

TYPE_PATTERNS = {
    "hardcoded_key": r"SecretKeySpec|Cipher\.getInstance|new\s+byte\s*\[\s*\]\s*\{|\"[A-Za-z0-9+/=]{16,}\"|IvParameterSpec",
    "cleartext_http": r"http://|HttpURLConnection|openConnection|Request\.Builder|new\s+URL\(|\.url\(",
    "tls_trust_all": r"checkServerTrusted|checkClientTrusted",
    "hostname_verifier": r"\bverify\s*\(|getPeerCertificates|HostnameVerifier",
    "insecure_random": r"new\s+Random\(|Math\.random\(|\.nextInt\(|\.nextLong\(|\.nextBytes\(|\.nextDouble\(",
}


def line_of(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def locate_method(jc: JavaClass, finding_type: str, lines: list[int] | None = None) -> JavaMethod | None:
    """Pick the best method to hook: contains a reported line, else scores highest on the type's pattern."""
    cands = [m for m in jc.methods if not m.is_abstract and m.name != "<clinit>"]
    if lines:
        for m in cands:
            lo, hi = line_of(jc.source, m.start), line_of(jc.source, m.end)
            if any(lo <= ln <= hi for ln in lines):
                return m
    pat = TYPE_PATTERNS.get(finding_type)
    if not pat:
        return None
    best, best_n = None, 0
    for m in cands:
        n = len(re.findall(pat, m.body))
        if n > best_n:
            best, best_n = m, n
    return best


# ---- recovering the real runtime class name -----------------------------------------------------

_PKG_DECL = re.compile(r"^package\s+([\w.]+)\s*;", re.M)
_TOP_CLASS_DECL = re.compile(r"^(?:(?:public|final|abstract|static)\s+)*(?:class|interface|enum|@interface)\s+(\w+)", re.M)
# jadx's own hardcoded placeholder (literally this string, verified against jadx's jar) for Java's default/unnamed
# package: classes with no real package still need *some* folder on disk, and jadx has used this exact name for
# that since early versions. It is a real `package defpackage;` line in the emitted source, not an absent one, so
# it has to be special-cased by this literal name -- there is no other way to tell it apart from a source-text read.
JADX_DEFAULT_PACKAGE = "defpackage"


def real_class_name(source: str, fallback: str) -> str:
    """The class name to pass to Java.use(), read from the source itself rather than trusted from a file path.

    A scanner (ours or MobSF) that derives a class name from the jadx file path gets this wrong for a class in
    Java's default package: `Java.use("defpackage.Foo")` then fails with ClassNotFoundException on a class that is
    really just `Foo`. R8/ProGuard's `-repackageclasses ''` option produces exactly this, by design: it moves every
    renamed class into the default package to shave a few more bytes off the APK.
    """
    pkg = _PKG_DECL.search(source)
    if pkg and pkg.group(1) == JADX_DEFAULT_PACKAGE:
        pkg = None
    decl = _TOP_CLASS_DECL.search(source)
    if decl is None:
        return fallback
    simple = fallback.rsplit(".", 1)[-1].split("$")[0]
    # jadx names the file after the (possibly inner) class the finding pointed at; the outer declaration may differ
    # for an inner/nested class file, so only override using the source's own name when it is the outer class.
    name = decl.group(1) if "$" not in fallback else simple
    return f"{pkg.group(1)}.{name}" if pkg else name

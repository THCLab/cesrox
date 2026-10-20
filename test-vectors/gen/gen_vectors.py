#!/usr/bin/env python3
"""
CESR V2 test-vector generator for cesrox / said, using keripy as the
reference implementation.

Usage (see generate.sh, which pins keripy and sets up the venv):
    <venv>/bin/python -I gen_vectors.py <out_dir> --keripy-rev <git rev>

Writes   <out_dir>/v2/{primitives,indexed,counters,streams,said,negative}/*.json
plus     <out_dir>/v2/manifest.json  (keripy commit, generator version, counts)

Every file is a JSON object:
    {"schema": "<kind>/1", "generator": {...}, "vectors": [ {...}, ... ]}

Vectors are deterministic: raw material is derived from sha512(label) so
reruns produce byte-identical output for the same keripy revision.
"""
import hashlib
import json
import argparse
import os
import sys
import warnings

warnings.filterwarnings("ignore")

from keri import kering
from keri.kering import Vrsn_2_0, Kinds, Protocols, versify, deversify
from keri.core import coring, indexing, counting, signing
from keri.core.coring import (Matter, MtrDex, Diger, Saider, Dater, Number,
                              Tagger, Texter, Bexter, Pather, Labeler, Verser,
                              DigDex)
from keri.core.indexing import Indexer, IdrDex, Siger
from keri.core.counting import Counter, CtrDex_2_0, Codens
from keri.core import eventing

GEN_VERSION = "0.2.0"


def det_bytes(label: str, n: int) -> bytes:
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha512(f"{label}/{i}".encode()).digest()
        i += 1
    return out[:n]


# --------------------------------------------------------------------------
# primitives (Matter)
# --------------------------------------------------------------------------

# Codes whose raw has semantic constraints are generated through their
# dedicated class below instead of from arbitrary bytes.
SPECIAL = {"Tag1", "Tag2", "Tag3", "Tag4", "Tag5", "Tag6", "Tag7", "Tag8",
           "Tag9", "Tag10", "Tag11", "DateTime", "GramHead", "Null", "No",
           "Yes", "Escape", "Empty", "TBD0S", "TBD0", "TBD1S", "TBD1",
           "TBD2S", "TBD2", "Label1", "Label2"}


def matter_vec(m: Matter, name: str, note: str = ""):
    hs, ss, xs, fs, ls = Matter.Sizes[m.code]
    v = {
        "id": f"matter/{name}/{m.qb64[:12]}",
        "name": name,
        "code": m.code,
        "soft": m.soft,
        "raw_hex": m.raw.hex(),
        "qb64": m.qb64,
        "qb2_hex": m.qb2.hex(),
        "sizes": {"hs": hs, "ss": ss, "xs": xs, "fs": fs, "ls": ls},
        "full_size": len(m.qb64),
    }
    if note:
        v["note"] = note
    return v


def gen_primitives():
    fixed, variable, special = [], [], []
    for name in vars(type(MtrDex))["__dataclass_fields__"]:
        code = getattr(MtrDex, name)
        hs, ss, xs, fs, ls = Matter.Sizes[code]
        if name in SPECIAL:
            continue
        if fs is not None and ss == 0:
            rs = Matter._rawSize(code)
            raw = det_bytes(f"matter/{name}", rs)
            fixed.append(matter_vec(Matter(raw=raw, code=code), name))
            # all-zero and all-0xff edge cases: exercise pad-bit handling
            fixed.append(matter_vec(Matter(raw=b"\x00" * rs, code=code), name, "all-zero raw"))
            fixed.append(matter_vec(Matter(raw=b"\xff" * rs, code=code), name, "all-0xff raw"))
        elif fs is None:
            # variable size: small and (for the big codes) a size that needs it
            for n in (0, 1, 2, 3, 4, 5, 33, 64):
                raw = det_bytes(f"matter/{name}/{n}", n)
                try:
                    m = Matter(raw=raw, code=code)
                except Exception:  # e.g. StrB64 needs b64 alphabet raw
                    continue
                variable.append(matter_vec(m, name, f"raw_len={n}"))
    # big-size variable: 4096 quadlets forces Big codes when built from small code
    raw = det_bytes("matter/bytes/big", 3 * 4096)
    variable.append(matter_vec(Matter(raw=raw, code=MtrDex.Bytes_L0), "Bytes_L0->Big",
                               "raw_len=12288 promotes to Big code"))

    # semantically constrained primitives through dedicated classes
    for tag in ("A", "AB", "icp", "rotx", "AbCdE", "AbCdEf", "AbCdEfG", "AbCdEfGh",
                "AbCdEfGhI", "AbCdEfGhIj", "AbCdEfGhIjK"):
        special.append(matter_vec(Tagger(tag=tag), f"Tag{len(tag)}", f"tag={tag}"))
    for dts in ("2020-08-22T17:50:09.988921+00:00", "2024-12-31T23:59:59.000000+00:00"):
        d = Dater(dts=dts)
        v = matter_vec(d, "DateTime"); v["dts"] = dts
        special.append(v)
    for num in (0, 1, 255, 65535, 65536, 2**32, 2**64 - 1, 2**128 - 1):
        n = Number(num=num)
        v = matter_vec(n, "Number:" + n.code); v["num"] = str(num); v["numh"] = n.numh
        special.append(v)
    for text in ("", "a", "ab", "abc", "Hello world!"):
        special.append(matter_vec(Texter(text=text), "Texter", f"text={text!r}"))
    for bext in ("-", "-A", "-A-", "-A-B", "-a-b-c", "-field0", "-field0-field1-field3", "A" * 300):
        b = Bexter(bext=bext)
        v = matter_vec(b, "Bexter"); v["bext"] = bext
        special.append(v)
    for path in (["a"], ["a", "b"], ["0"], ["a", "1", "c"]):
        try:
            p = Pather(parts=path)
        except Exception:
            continue
        v = matter_vec(p, "Pather"); v["path_parts"] = path
        special.append(v)
    for label in ("a", "ab", "abc", "d", "dt", "label_with_more"):
        try:
            l = Labeler(label=label)
        except Exception:
            continue
        v = matter_vec(l, "Labeler:" + l.code); v["label"] = label
        special.append(v)
    for code in ("1AAK", "1AAL", "1AAM", "1AAP"):
        special.append(matter_vec(Matter(raw=b"", code=code), Matter.Names[code]))
    special.append(matter_vec(Verser(proto=Protocols.keri, pvrsn=Vrsn_2_0), "Verser", "KERI 2.0"))
    return {"primitives/fixed.json": ("matter/1", fixed),
            "primitives/variable.json": ("matter/1", variable),
            "primitives/special.json": ("matter/1", special)}


# --------------------------------------------------------------------------
# indexed signatures (Indexer)
# --------------------------------------------------------------------------

def gen_indexed():
    vecs = []
    for name in vars(type(IdrDex))["__dataclass_fields__"]:
        code = getattr(IdrDex, name)
        if name.startswith("TBD"):
            continue
        hs, ss, os_, fs, ls = Indexer.Sizes[code]
        rs = Indexer._rawSize(code)
        raw = det_bytes(f"indexer/{name}", rs)
        ms = ss - os_
        maxi = 64 ** ms - 1
        maxo = 64 ** os_ - 1 if os_ else 0
        cases = {(0, None), (1, None), (maxi, None)}
        if os_:
            cases |= {(0, 0), (3, 2), (maxi, maxo), (1, maxo)}
        for index, ondex in sorted(cases, key=lambda t: (t[0], -1 if t[1] is None else t[1])):
            try:
                i = Indexer(raw=raw, code=code, index=index, ondex=ondex)
            except Exception:
                continue
            vecs.append({
                "id": f"indexer/{name}/{index}/{ondex}",
                "name": name, "code": i.code, "index": i.index, "ondex": i.ondex,
                "raw_hex": i.raw.hex(), "qb64": i.qb64, "qb2_hex": i.qb2.hex(),
                "sizes": {"hs": hs, "ss": ss, "os": os_, "fs": fs, "ls": ls},
            })
    return {"indexed/indexers.json": ("indexer/1", vecs)}


# --------------------------------------------------------------------------
# counters (Counter V2)
# --------------------------------------------------------------------------

def gen_counters():
    vecs = []
    for name in vars(type(CtrDex_2_0))["__dataclass_fields__"]:
        code = getattr(CtrDex_2_0, name)
        if code.startswith("-_"):
            continue
        hs, ss, fs = Counter.Sizes[2][0][code]
        maxc = 64 ** ss - 1
        for count in sorted({0, 1, 63, 64, 4095, maxc} if code.startswith("--")
                            else {0, 1, 63, 64, 4095}):
            if count > maxc:
                continue
            c = Counter(code=code, count=count, version=Vrsn_2_0)
            vecs.append({"id": f"counter/{name}/{count}", "name": name, "code": c.code,
                         "count": c.count, "qb64": c.qb64, "qb2_hex": c.qb2.hex(),
                         "sizes": {"hs": hs, "ss": ss, "fs": fs}, "version": "2.0"})
    # counter auto-promotion: count too big for small code
    for name in ("ControllerIdxSigs", "GenericGroup", "AttachmentGroup"):
        code = getattr(CtrDex_2_0, name)
        enc = Counter.enclose(qb64=b"A" * 4 * 4096, code=name, version=Vrsn_2_0)
        vecs.append({"id": f"counter/{name}/enclose-4096", "name": name,
                     "note": "Counter.enclose of 4096 quadlets promotes to big code",
                     "qb64": bytes(enc[:8]).decode(), "count": 4096})
    # genus version codes
    for gv in (Vrsn_2_0, kering.Versionage(1, 0)):
        gvc = Counter.makeGVC(version=gv) if hasattr(Counter, "makeGVC") else None
        vecs.append({"id": f"genus/KERIACDC/{gv.major}.{gv.minor}", "name": "KERIACDCGenusVersion",
                     "code": "-_AAA", "major": gv.major, "minor": gv.minor,
                     "qb64": gvc.decode() if isinstance(gvc, (bytes, bytearray)) else gvc})
    return {"counters/counters.json": ("counter/1", vecs)}


# --------------------------------------------------------------------------
# attachment and seal groups built from keripy primitives
# --------------------------------------------------------------------------

def gen_groups():
    from keri.core.coring import Prefixer, Dater, Noncer, Verser
    vecs = []
    signers = [signing.Signer(raw=det_bytes(f"group/seed/{k}", 32), transferable=True)
               for k in range(2)]
    nsigner = signing.Signer(raw=det_bytes("group/seed/nt", 32), transferable=False)
    ser = b"group vectors"
    sigers = [s.sign(ser=ser, index=i) for i, s in enumerate(signers)]
    cigar = nsigner.sign(ser=ser)
    dig = lambda label: Diger(ser=label.encode())
    pre = lambda label: Prefixer(qb64=dig(label).qb64)
    num = lambda n: Number(num=n)

    def group(name, items):
        body = b"".join(b"".join(p.qb64b for p in item) for item in items)
        qb64 = bytes(Counter.enclose(qb64=body, code=name, version=Vrsn_2_0)).decode()
        vecs.append({"id": f"group/{name}", "name": name, "items": len(items), "qb64": qb64})

    def nested(name, prefix_items, sigs):
        # each entry ends with a -K group of its signatures
        body = b""
        for item in prefix_items:
            body += b"".join(p.qb64b for p in item)
            body += bytes(Counter.enclose(qb64=b"".join(s.qb64b for s in sigs),
                                          code="ControllerIdxSigs", version=Vrsn_2_0))
        qb64 = bytes(Counter.enclose(qb64=body, code=name, version=Vrsn_2_0)).decode()
        vecs.append({"id": f"group/{name}", "name": name, "items": len(prefix_items),
                     "qb64": qb64})

    group("ControllerIdxSigs", [[s] for s in sigers])
    group("WitnessIdxSigs", [[s] for s in sigers])
    group("NonTransReceiptCouples", [[nsigner.verfer, cigar]])
    group("FirstSeenReplayCouples", [[num(0), Dater(dts="2020-08-22T17:50:09.988921+00:00")],
                                     [num(70000), Dater(dts="2024-12-31T23:59:59.000000+00:00")]])
    group("DigestSealSingles", [[dig("a")], [dig("b")]])
    group("MerkleRootSealSingles", [[dig("root")]])
    group("SealSourceCouples", [[num(1), dig("s1")], [num(2**64), dig("s2")]])
    group("SealSourceTriples", [[pre("t"), num(3), dig("t3")]])
    group("SealSourceLastSingles", [[pre("u1")], [pre("u2")]])
    group("BackerRegistrarSealCouples", [[pre("backer"), dig("registrar")]])
    group("TypedDigestSealCouples", [[Verser(proto=Protocols.keri, pvrsn=Vrsn_2_0),
                                      Noncer(nonce=dig("typed").qb64)]])
    group("BlindedStateQuadruples", [[Noncer(nonce=dig("blind").qb64),
                                      Noncer(raw=det_bytes("uuid", 16)),
                                      Noncer(nonce=dig("tel").qb64),
                                      Labeler(label="issued")]])
    group("BoundStateSextuples", [[Noncer(nonce=dig("blind").qb64),
                                   Noncer(raw=det_bytes("uuid", 16)),
                                   Noncer(nonce=dig("tel").qb64),
                                   Labeler(label="issued"),
                                   num(5),
                                   Noncer(nonce=dig("kel").qb64)]])
    group("TypedMediaQuadruples", [[Noncer(nonce=dig("media").qb64),
                                    Noncer(raw=det_bytes("uuid", 16)),
                                    Labeler(text="application/json"),
                                    Texter(text='{"a":1}')]])
    nested("TransIdxSigGroups", [[pre("x"), num(7), dig("x7")]], sigers)
    nested("TransLastIdxSigGroups", [[pre("y")]], sigers)
    return {"groups/groups.json": ("group/1", vecs)}


# --------------------------------------------------------------------------
# streams (full V2 messages with attachments)
# --------------------------------------------------------------------------

def tokens_of(qb64: str):
    """Flatten a CESR text stream into a token list using keripy primitives,
    so a consumer can compare element by element. Bodies are recognised via
    the version string."""
    toks, i = [], 0
    b = qb64.encode()
    while i < len(b):
        c = chr(b[i])
        if c == "{":
            sm = kering.smell(b[i:])
            toks.append({"t": "body", "kind": sm.kind, "size": sm.size,
                         "proto": sm.proto, "pvrsn": list(sm.pvrsn)})
            i += sm.size
        elif c == "-":
            ctr = Counter(qb64b=b[i:], version=Vrsn_2_0)
            toks.append({"t": "counter", "code": ctr.code, "name": ctr.name, "count": ctr.count})
            i += len(ctr.qb64)
        else:
            # indexer if previous counter is an idx-sig group, else matter
            prev = next((t for t in reversed(toks) if t["t"] == "counter"), None)
            if prev and prev["name"] in ("ControllerIdxSigs", "WitnessIdxSigs",
                                         "BigControllerIdxSigs", "BigWitnessIdxSigs"):
                x = Indexer(qb64b=b[i:])
                toks.append({"t": "indexer", "code": x.code, "index": x.index,
                             "ondex": x.ondex, "qb64": x.qb64})
                i += len(x.qb64)
            else:
                m = Matter(qb64b=b[i:])
                toks.append({"t": "matter", "code": m.code, "qb64": m.qb64})
                i += len(m.qb64)
    return toks


def gen_streams():
    vecs = []
    signers = [signing.Signer(raw=det_bytes(f"seed/{k}", 32), transferable=True) for k in range(3)]
    nsigner = signing.Signer(raw=det_bytes("seed/nt", 32), transferable=False)
    keys = [s.verfer.qb64 for s in signers]
    ndigs = [Diger(ser=s.verfer.qb64b).qb64 for s in signers]
    for kind in (Kinds.json, Kinds.cbor, Kinds.mgpk, Kinds.cesr):
        srdr = eventing.incept(keys=keys, isith="2", ndigs=ndigs, nsith="2",
                               pvrsn=Vrsn_2_0, kind=kind)
        sigers = [s.sign(ser=srdr.raw, index=i) for i, s in enumerate(signers)]
        msg = eventing.messagize(srdr, sigers=sigers, gvrsn=Vrsn_2_0)
        entry = {"id": f"stream/icp/{kind}/3sig", "proto": "KERI", "pvrsn": "2.0",
                 "kind": kind, "body_said": srdr.said, "body_len": len(srdr.raw),
                 "sigs_verkeys": keys,
                 "stream_b64": None, "stream_hex": bytes(msg).hex()}
        if kind in (Kinds.json, Kinds.cesr):
            entry["stream"] = bytes(msg).decode()
        if kind == Kinds.json:
            entry["tokens"] = tokens_of(entry["stream"])
        vecs.append(entry)

    # receipt by non-transferable witness + interaction with seal
    srdr = eventing.incept(keys=keys, isith="2", ndigs=ndigs, nsith="2",
                           pvrsn=Vrsn_2_0, kind=Kinds.json)
    rct = eventing.receipt(pre=srdr.pre, sn=0, said=srdr.said, pvrsn=Vrsn_2_0, kind=Kinds.json)
    cigar = nsigner.sign(ser=srdr.raw)
    msg = eventing.messagize(rct, cigars=[cigar], gvrsn=Vrsn_2_0)
    vecs.append({"id": "stream/rct/json/cigar", "stream": bytes(msg).decode(),
                 "tokens": tokens_of(bytes(msg).decode())})

    # transferable last-est signature group (-Y) on a query
    qry = eventing.query(pre=srdr.pre, route="ksn", query=dict(i=srdr.pre, src=srdr.pre),
                         stamp="2024-01-01T00:00:00.000000+00:00", pvrsn=Vrsn_2_0, kind=Kinds.json)
    sigers = [s.sign(ser=qry.raw, index=i) for i, s in enumerate(signers[:2])]
    from keri.core.coring import Prefixer
    msg = eventing.messagize(qry, lsgs=[(Prefixer(qb64=srdr.pre), sigers)], gvrsn=Vrsn_2_0)
    vecs.append({"id": "stream/qry/json/lsgs", "stream": bytes(msg).decode(),
                 "tokens": tokens_of(bytes(msg).decode())})

    # genus-prefixed stream
    msg = eventing.messagize(srdr, sigers=[signers[0].sign(ser=srdr.raw, index=0)],
                             gvrsn=Vrsn_2_0, genusify=True)
    vecs.append({"id": "stream/icp/json/genusify", "stream": bytes(msg).decode(),
                 "tokens": tokens_of(bytes(msg).decode())})

    # framed=True wraps the message and its attachments in a counted group
    msg = eventing.messagize(srdr, sigers=[signers[0].sign(ser=srdr.raw, index=0)],
                             gvrsn=Vrsn_2_0, framed=True)
    vecs.append({"id": "stream/icp/json/framed", "stream": bytes(msg).decode(),
                 "tokens": tokens_of(bytes(msg).decode())})
    return {"streams/messages.json": ("stream/1", vecs)}


# --------------------------------------------------------------------------
# said: digests, saidify, version strings
# --------------------------------------------------------------------------

def gen_said():
    digests, saidify, versions = [], [], []
    inputs = [b"", b"hello there", det_bytes("said/input", 1000)]
    for name in vars(type(DigDex))["__dataclass_fields__"]:
        code = getattr(DigDex, name)
        for data in inputs:
            d = Diger(raw=Diger._digest(ser=data, code=code), code=code)
            digests.append({"id": f"digest/{name}/{len(data)}", "name": name, "code": code,
                            "input_hex": data.hex(), "digest_hex": d.raw.hex(), "qb64": d.qb64})
    # saidify plain SADs (no version string), JSON/CBOR/MGPK
    base = {"d": "", "text": "Hello world", "n": 1, "nested": {"a": [1, 2, 3]}}
    for code in (DigDex.Blake3_256, DigDex.SHA3_256, DigDex.Blake2b_256, DigDex.SHA2_512):
        for kind in (Kinds.json, Kinds.cbor, Kinds.mgpk):
            saider, sad = Saider.saidify(sad=dict(base), code=code, kind=kind)
            ser = coring.dumps(sad, kind=kind)
            dummy = dict(sad); dummy["d"] = "#" * Matter.Sizes[code].fs
            saidify.append({"id": f"saidify/{code}/{kind}", "code": code, "kind": kind,
                            "label": "d", "sad_in_json": json.dumps(base, separators=(",", ":")),
                            "said": saider.qb64,
                            "derivation_input_hex": coring.dumps(dummy, kind=kind).hex(),
                            "sad_out_hex": ser.hex()})
    # V2 versioned SAD via Serder (KERI icp) and ACDC-like map with v field
    for proto in (Protocols.keri, Protocols.acdc):
        for kind in (Kinds.json, Kinds.cbor, Kinds.mgpk):
            sad = {"v": versify(proto=proto, pvrsn=Vrsn_2_0, kind=kind, size=0),
                   "d": "", "text": "Hello world"}
            if proto == Protocols.keri:
                continue  # KERI bodies covered by streams
            saider, out = Saider.saidify(sad=dict(sad), code=DigDex.Blake3_256, kind=kind)
            saidify.append({"id": f"saidify-versioned/{proto}/{kind}", "code": "E",
                            "kind": kind, "label": "d",
                            "sad_in_json": json.dumps(sad, separators=(",", ":")),
                            "said": saider.qb64,
                            "sad_out_hex": coring.dumps(out, kind=kind).hex(),
                            "note": "saidify also sets the size field of the version string"})
    # serder V2 makify (size + said fixed by keripy)
    keys = [signing.Signer(raw=det_bytes("seed/0", 32)).verfer.qb64]
    for kind in (Kinds.json, Kinds.cbor, Kinds.mgpk):
        srdr = eventing.incept(keys=keys, pvrsn=Vrsn_2_0, kind=kind)
        saidify.append({"id": f"serder/KERI/icp/{kind}", "kind": kind, "code": "E",
                        "label": "d", "raw_hex": srdr.raw.hex(), "said": srdr.said,
                        "vs": srdr.sad["v"], "size": srdr.size})
    # version strings
    for proto in (Protocols.keri, Protocols.acdc):
        for kind in (Kinds.json, Kinds.cbor, Kinds.mgpk, Kinds.cesr):
            for size in (0, 100, 4095, 64 ** 4 - 1):
                for gv in (None, kering.Versionage(2, 1)):
                    vs = versify(proto=proto, pvrsn=Vrsn_2_0, kind=kind, size=size, gvrsn=gv)
                    sm = deversify(vs)
                    versions.append({"id": f"vs/{vs}", "vs": vs, "proto": sm.proto,
                                     "pvrsn": list(sm.pvrsn), "gvrsn": list(sm.gvrsn),
                                     "kind": sm.kind, "size": sm.size})
    return {"said/digests.json": ("digest/1", digests),
            "said/saidify.json": ("saidify/1", saidify),
            "said/version_strings.json": ("versionstring/1", versions)}


# --------------------------------------------------------------------------
# negative vectors: keripy must reject; record the error class
# --------------------------------------------------------------------------

def reject(target, inp, why):
    ctor = {"matter": lambda s: Matter(qb64=s),
            "indexer": lambda s: Indexer(qb64=s),
            "counter": lambda s: Counter(qb64=s, version=Vrsn_2_0),
            "version": lambda s: deversify(s)}[target]
    try:
        ctor(inp)
        err = None
    except Exception as ex:
        err = type(ex).__name__
    return {"id": f"neg/{target}/{why}", "target": target, "input": inp, "why": why,
            "keripy_accepts": err is None, "keripy_error": err}


def gen_negative():
    d = Diger(ser=b"x").qb64
    sig = Indexer(raw=det_bytes("neg/sig", 64), code="A", index=0).qb64
    vecs = [
        reject("matter", "", "empty"),
        reject("matter", "E", "code-only"),
        reject("matter", d[:-1], "truncated-1"),
        reject("matter", d[:10], "truncated-10"),
        reject("matter", "0", "two-char-selector-truncated"),
        reject("matter", "1AA", "four-char-selector-truncated"),
        reject("matter", "E" + "!" * 43, "non-b64-char"),
        reject("matter", "E" + "A" * 42 + "B", "nonzero-pad-bits-or-ok"),
        reject("matter", "B" + "_" * 43, "pad-bits-set-in-lead"),
        reject("matter", "0BAA", "sig-truncated"),
        reject("matter", "XAB", "tag3-truncated"),
        reject("matter", "Y", "tag7-truncated"),
        reject("matter", "4BAB", "varlen-declares-1-quadlet-missing"),
        reject("matter", "5BABAA", "varlen-L1-short"),
        reject("matter", "5BAB_AAA", "varlen-L1-nonzero-lead-byte"),
        reject("matter", "6BABAAAB", "varlen-L2-nonzero-lead-byte"),
        reject("matter", "4ZAB", "varlen-unknown-type"),
        reject("matter", "~AAA", "invalid-selector"),
        reject("matter", "1AAGnot-a-date-time-at-all-xxxxxxxxx", "datetime-garbage"),
        reject("indexer", sig[:-1], "truncated"),
        reject("indexer", "A", "code-only"),
        reject("indexer", "2A", "big-code-only"),
        reject("indexer", "0A", "ed448-code-only"),
        reject("indexer", "Z" + sig[1:], "unknown-code"),
        reject("indexer", "B" + "B" + sig[2:], "crt-only-with-ondex? (B has no ondex)"),
        reject("indexer", "2BABAB" + sig[6:] + "AAAA", "big-crt-nonzero-ondex"),
        reject("counter", "", "empty"),
        reject("counter", "-", "dash-only"),
        reject("counter", "-K", "no-count"),
        reject("counter", "-KA", "count-truncated"),
        reject("counter", "--K", "big-no-count"),
        reject("counter", "-_AAA", "genus-truncated"),
        reject("counter", "-_ZZZCAA", "unknown-genus"),
        reject("counter", "-!AA", "non-b64-count-code"),
        reject("counter", "-K!!", "non-b64-count"),
        reject("version", "KERI10JSON000064_", "v1-version-string-in-v2-only-context"),
        reject("version", "KERICAACAAJSONAABk", "v2-missing-terminator"),
        reject("version", "KERIBAACAAJSONAABk.", "v2-wrong-major-1"),
        reject("version", "KERICAABAAJSONAABk.", "v2-wrong-genus-major-1"),
        reject("version", "KERICAACAAXXXXAABk.", "v2-unknown-kind"),
        reject("version", "XXXXCAACAAJSONAABk.", "v2-unknown-proto"),
    ]
    # stream-level negatives: counter declares more quadlets than present
    good = Counter.enclose(qb64=sig.encode(), code="ControllerIdxSigs", version=Vrsn_2_0)
    vecs.append({"id": "neg/stream/group-overrun", "target": "stream",
                 "input": bytes(good)[:-4].decode(), "why": "group counter overruns stream",
                 "keripy_accepts": False, "keripy_error": "ShortageError (by construction)"})
    vecs.append({"id": "neg/stream/group-underrun", "target": "stream",
                 "input": "-KAX" + sig + "AAAA", "why": "count says 23 quadlets but content is 22+1 junk quadlet",
                 "keripy_accepts": None, "keripy_error": "content not an indexer at quadlet 22"})
    vecs.append({"id": "neg/stream/nonb64-byte", "target": "stream",
                 "input": "E" + "A" * 20 + "é" + "A" * 21, "why": "non-ASCII byte inside primitive",
                 "keripy_accepts": False, "keripy_error": "by construction"})
    rejected = [v for v in vecs if v["keripy_accepts"] is not True]
    accepted = [v for v in vecs if v["keripy_accepts"] is True]
    return {"negative/negative.json": ("negative/1", rejected),
            "negative/keripy_accepts_edge.json": ("edge/1", accepted)}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("out_dir")
    ap.add_argument("--keripy-rev", required=True, help="keripy git revision the venv was built from")
    args = ap.parse_args()
    out = args.out_dir
    gen = {"tool": "gen_vectors.py", "version": GEN_VERSION, "keripy_rev": args.keripy_rev,
           "keripy_version": __import__("keri").__version__}
    manifest = {"generator": gen, "files": {}}
    for fn in (gen_primitives, gen_indexed, gen_counters, gen_groups, gen_streams, gen_said,
               gen_negative):
        for rel, (schema, vecs) in fn().items():
            ids = [v["id"] for v in vecs]
            dups = sorted({i for i in ids if ids.count(i) > 1})
            if dups:
                sys.exit(f"{rel}: duplicate vector ids {dups}")
            path = os.path.join(out, "v2", rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                json.dump({"schema": schema, "generator": gen, "vectors": vecs}, f,
                          indent=1, sort_keys=False, ensure_ascii=False)
                f.write("\n")
            manifest["files"][rel] = len(vecs)
    with open(os.path.join(out, "v2", "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=1, sort_keys=True)
        f.write("\n")
    print(json.dumps(manifest, indent=1))


if __name__ == "__main__":
    main()

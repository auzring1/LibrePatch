#!/usr/bin/env python3
"""Writes mini-source2.msix: a small, synthetic file in the layout of the winget source index (format version 2).

Run it from this directory:  python3 make_fixture.py
The tests read the result; the data is invented (the real index is downloaded at run time), but large enough that the
b-trees have interior pages."""
import sqlite3, zipfile, io, os, struct

SCHEMA = """
CREATE TABLE [metadata]([name] TEXT PRIMARY KEY NOT NULL, [value] TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE [packages](rowid INTEGER PRIMARY KEY, [id] TEXT NOT NULL, [name] TEXT NOT NULL, [moniker] TEXT, [latest_version] TEXT NOT NULL, [arp_min_version] TEXT, [arp_max_version] TEXT, [hash] BLOB);
CREATE TABLE [productcodes2]([productcode] TEXT NOT NULL, [package] INT64 NOT NULL, PRIMARY KEY([productcode], [package])) WITHOUT ROWID;
CREATE TABLE [norm_names2]([norm_name] TEXT NOT NULL, [package] INT64 NOT NULL, PRIMARY KEY([norm_name], [package])) WITHOUT ROWID;
CREATE TABLE [norm_publishers2]([norm_publisher] TEXT NOT NULL, [package] INT64 NOT NULL, PRIMARY KEY([norm_publisher], [package])) WITHOUT ROWID;
CREATE TABLE [tags2](rowid INTEGER PRIMARY KEY, [tag] TEXT NOT NULL);
"""

REAL = [  # id, name, moniker, latest, product codes, norm names, norm publishers
    ("Google.Chrome", "Google Chrome", "chrome", "155.0.8059.40", ["{74badaf7-9d73-386e-b2e4-2d4b3416a469}", "{ae41646d-561a-3316-9b94-dd3ea96ef975}"], ["googlechrome"], ["google"]),
    ("Mozilla.Firefox", "Mozilla Firefox (en-US)", "firefox", "157.0.1", ["mozilla firefox", "{11111111-2222-3333-4444-555555555555}"], ["mozillafirefox", "mozillafirefox(X64)", "mozillafirefox(X86)"], ["mozilla"]),
    ("Mozilla.Firefox.ESR", "Mozilla Firefox ESR", "firefox-esr", "140.4.0", ["mozilla firefox"], ["mozillafirefoxesr"], ["mozilla"]),
    ("Notepad++.Notepad++", "Notepad++", "notepad++", "8.9.8.1", ["notepad++"], ["notepad"], ["notepadteam"]),
    ("Zoom.Zoom", "Zoom Workplace", "zoom", "6.7.0.1234", ["{aaaaaaaa-0000-0000-0000-000000000001}"], ["zoom", "zoom(X64)", "zoomworkplace"], ["zoom"]),
    ("Microsoft.Edge", "Microsoft Edge", "", "155.0.4283.45", ["{9459c573-b17a-45aa-bd40-33d76168b4de}"], ["microsoftedge"], ["microsoft"]),
    ("Splashtop.SplashtopStreamer", "Splashtop Streamer", "", "3.8.6.3", [], ["splashtopstreamer"], ["splashtop"]),
    ("7zip.7zip", "7-Zip", "7zip", "26.04", ["7-zip"], ["7zip"], ["igorpavlov"]),
    # Two editions that share one uninstall key and one normalized name (like Citrix Workspace's current and LTSR releases).
    ("Citrix.Workspace", "Citrix Workspace", "", "26.8.0.100", ["citrixonlinepluginpackweb"], ["citrixworkspace"], ["citrixsystems"]),
    ("Citrix.Workspace.LTSR", "Citrix Workspace LTSR", "", "26.7.1.4", ["citrixonlinepluginpackweb"], ["citrixworkspace"], ["citrixsystems"]),
    ("MicroSIP.MicroSIP", "MicroSIP", "microsip", "3.22.19", [], ["microsip"], ["microsip"]),
]

def build():
    db = sqlite3.connect(":memory:")
    db.executescript(SCHEMA)
    db.execute("PRAGMA page_size=4096")
    db.executemany("INSERT INTO metadata VALUES (?,?)", [("databaseIdentifier", "{00000000-0000-0000-0000-000000000000}"), ("lastwritetime", "1791572758"), ("majorVersion", "2"), ("minorVersion", "0")])
    rows = list(REAL)
    for i in range(700):  # filler so the b-trees need interior pages
        rows.append((f"Vendor{i}.App{i}", f"Filler App {i}", "", f"{i % 9}.{i % 7}.{i}", [f"{{{i:08x}-0000-4000-8000-{j:012x}}}" for j in range(5)], [f"fillerapp{i}"], [f"vendor{i}"]))
    for rid, (pid, name, mon, ver, pcs, nns, nps) in enumerate(rows, start=1):
        db.execute("INSERT INTO packages(rowid,id,name,moniker,latest_version,hash) VALUES (?,?,?,?,?,?)", (rid, pid, name, mon or None, ver, b"\x00" * 32))
        for pc in pcs: db.execute("INSERT INTO productcodes2 VALUES (?,?)", (pc, rid))
        for n in nns: db.execute("INSERT INTO norm_names2 VALUES (?,?)", (n, rid))
        for p in nps: db.execute("INSERT INTO norm_publishers2 VALUES (?,?)", (p, rid))
    db.commit()
    data = db.serialize()
    return bytes(data)

if __name__ == "__main__":
    data = build()
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AppxManifest.xml", "<Package/>")
        z.writestr("Public/index.db", data)
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "mini-source2.msix"), "wb") as f:
        f.write(out.getvalue())
    print("wrote", len(out.getvalue()), "bytes;", len(data) // 4096, "pages")

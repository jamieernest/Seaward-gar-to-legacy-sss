#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Convert an Apollo 500 Plus GAR/SSS export into the legacy Seaward SSS
# format understood by portableappliancetest.py (and by extension, any
# importer built against that format).
#
# There is no vendor spec for the Apollo record layout; the field offsets,
# scale factors, and legacy-code mapping below were reverse-engineered from
# real exports across two different meters, cross-checked against
# PATGuard3's displayed values and, for the pass/fail bits, real confirmed
# pass/fail outcomes.
#
# Known gaps (approximations, not bugs):
#  - testcode1/testcode2 (legacy config barcodes) have no known Apollo
#    equivalent and are left blank.
#  - F2's "current" (test current selector) and E0's mapping bytes are set
#    to the values seen in every piece of real ground truth we had; Apollo
#    doesn't expose these either.
#  - Continuity and Polarity readings carry a confirmed pass/fail bit and
#    convert faithfully either way. Insulation, Load Current, and Touch
#    Current don't -- no failing example of any of those three has turned
#    up yet, so a reading found at all is always treated as passed.
#  - A record where Apollo genuinely recorded nothing (an aborted test that
#    never got as far as taking any reading, as opposed to one that took a
#    reading and failed it) converts to a bare Overall Fail with no
#    per-test detail, since there is no per-test detail to convert.

import csv
import os
import re
import struct
import sys
import time

import gar


def extract_sss_bytes(gar_path):
    # Accept an already-extracted raw Apollo .sss directly (e.g. one
    # extracted previously, or handed over separately from its source
    # .gar) rather than always requiring a compressed .gar container.
    if gar_path.lower().endswith('.sss'):
        with open(gar_path, 'rb') as f:
            return f.read()
    gar.gar_extract(gar_path)
    out_name = gar_path.rsplit('.', 1)[0] + '_TestResults.sss'
    with open(out_name, 'rb') as f:
        return f.read()


def legacy_encode(value, max_exp=3):
    """Inverse of portableappliancetest.py's SSS.rescale(): pack a float into
    the 2-bit-exponent/14-bit-mantissa halfword used throughout the legacy
    format."""
    value = max(0.0, value)
    for exp in range(max_exp, -1, -1):
        mantissa = round(value * (10 ** exp))
        if mantissa <= 0x3fff:
            return (exp << 14) | mantissa
    return 0x3fff


def pack_str(s, size):
    return s.encode('latin-1', 'replace')[:size].ljust(size, b'\x00')


# ---------------------------------------------------------------------------
# Apollo record parsing
# ---------------------------------------------------------------------------

PRINTABLE_RUN = re.compile(rb'[\x20-\x7e]{2,}')
SUITE_RE = re.compile(rb'BTS - [\x20-\x7e]+?\x00')
# Second marker byte is 0x01 for normal auto-numbered assets but 0x02 for at
# least the manually-imported/manufactured samples seen (e.g. "IMPORTTEST1"),
# and those use an alphanumeric id rather than pure digits -- accept both.
SEQID_RE = re.compile(rb'\x01[\x01\x02]([0-9A-Za-z]{4,20})')


def find_apollo_records(data):
    markers = [m.start() for m in re.finditer(rb'\xff\x55', data)]
    records = []
    for i in range(len(markers)):
        start = markers[i]
        end = markers[i + 1] if i + 1 < len(markers) else len(data)
        records.append(data[start:end])
    return records


def parse_text_fields(rec):
    """id/site/location sit at fixed offsets relative to the '01 01' marker
    that precedes the ascii sequence id (verified against multiple real
    records: a constant 64-byte id buffer, a 16-byte binary blob of unknown
    purpose, then two 16-byte text fields). Using fixed offsets for these
    avoids false-positive matches from incidental printable bytes inside the
    binary blob (e.g. 0x4c,0x68 = 'Lh') that a purely positional text-run
    scan would otherwise pick up ahead of the real fields.

    Between location and tester sits a 7-byte timestamp -- hour, minute,
    second, day, month, year(2 bytes, little-endian) -- the real per-record
    date/time Apollo carries. Confirmed against 219 real records
    cross-checked with a companion CSV export (218 exact matches; the 1
    "mismatch" was a genuine duplicate test on an earlier date that the
    CSV's "last test" summary didn't retain, i.e. this field was actually
    more correct than the CSV).

    tester is itself a fixed 16-byte buffer; description/notes/make/model
    immediately follow tester as a single '\\n'-joined, null-terminated
    blob with no fixed width (seen up to 25 chars per segment, so a
    generous read-and-truncate window is used)."""
    seq_match = SEQID_RE.search(rec)
    if not seq_match:
        return None
    id_field_start = seq_match.start() + 2
    blob_start = id_field_start + 64
    site_start = blob_start + 16
    location_start = site_start + 16
    timestamp_start = location_start + 16
    tester_start = timestamp_start + 7
    description_start = tester_start + 16

    def read_fixed(start, size):
        return rec[start:start + size].split(b'\x00')[0].decode('latin-1', 'replace')

    site = read_fixed(site_start, 16)
    location = read_fixed(location_start, 16)
    tester = read_fixed(tester_start, 16)
    # The field at description_start is actually up to 4 '\n'-separated
    # segments: description, notes, make, model (later segments are often
    # just a lone space when unused, e.g. "16A 12 Way\nRDB\n \n \n").
    desc_lines = read_fixed(description_start, 100).split('\n')
    desc_lines = [s.strip() for s in desc_lines] + [''] * 4

    ts = rec[timestamp_start:timestamp_start + 7]
    when = None
    if len(ts) == 7:
        hour, minute, second, day, month = ts[0], ts[1], ts[2], ts[3], ts[4]
        year = struct.unpack('<H', ts[5:7])[0]
        if 1 <= day <= 31 and 1 <= month <= 12 and 2000 <= year <= 2099:
            try:
                when = time.strptime(
                    '%04d-%02d-%02d %02d:%02d:%02d' % (year, month, day, hour, minute, second),
                    '%Y-%m-%d %H:%M:%S')
            except ValueError:
                when = None  # e.g. an invalid combination like day 31 in April

    suite_match = SUITE_RE.search(rec, description_start)
    suite = suite_match.group().rstrip(b'\x00').decode('latin-1') if suite_match else None
    return {
        'when': when,
        'seqid': seq_match.group(1).decode(),
        'site': site,
        'location': location,
        'tester': tester,
        'description': desc_lines[0],
        'notes': desc_lines[1],
        'make': desc_lines[2],
        'model': desc_lines[3],
        'suite': suite,
        'description_start': description_start,
    }


def parse_electrical(rec, description_start):
    """Scan for every known reading pattern directly, rather than deciding
    which patterns to expect based on the suite name. Suite-name dispatch
    turned out to be fragile: different testers configure the same suite
    name with entirely different subsets of tests (one meter's plain
    "Sensitive II" always includes Insulation, another's never does; one
    tester's "Alphapack" is continuity-only), and other testers invent
    suite names we've never seen at all. Every pattern below has its own
    distinctive byte signature reverse-engineered from real ground truth
    across two different meters, so they're all searched for
    unconditionally and whatever is actually found is used -- no suite
    name needed.

    Where the scan starts (three-tier fallback, tried in order):
      1. Right after '\\xfc\\x48\\x00' -- present immediately before the
         electrical section in most records, but NOT universal: one
         meter's "Sensitive I"/"Grelco" records never had it at all, while
         another meter's versions of those same suite names do.
      2. Right after the suite name text, when there is one but no
         '\\xfc\\x48\\x00' was found.
      3. Right after description/notes/make/model, when there's no suite
         name either (e.g. a record cut short before ever reaching it).

    Tier 3's region can include generic per-record checklist-boilerplate
    bytes that happen to contain a stray 0x00 0x40 which isn't a real
    touch-current reading -- so the touch fallback below additionally
    requires the same high-byte sanity check (0xc0-0xff) used for Earth
    Continuity, which every genuine reading has satisfied and which the
    filler bytes don't."""
    fc4800 = rec.find(b'\xfc\x48\x00')
    if fc4800 != -1:
        tail = rec[fc4800 + 3:]
    else:
        suite_match = SUITE_RE.search(rec)
        tail = rec[suite_match.end():] if suite_match else rec[description_start:]

    # Per-socket continuity readings: 0x16 <value> <status1> <status2>,
    # repeated. value/1000 = ohms. status1 varies (seen 0xc0/0xc1, confirmed
    # NOT a pass/fail indicator -- both values verified passing in PATGuard)
    # status2 is 0x01 in ~1288/1291 genuine readings (pass), but a confirmed
    # real-world failure (asset with a "FAIL" note, cross-checked against
    # PATGuard) recorded its one reading as 0x16<val><0xc1>0x02 with nothing
    # else in the record -- i.e. Apollo *does* keep the actual failing
    # reading rather than discarding it like it does for other test types.
    # Restricting to exactly {0x01, 0x02} still rejects the one confirmed
    # garbage case (a manufactured aborted-test sample left a stray
    # 0x16<val>0x87 0x22 fragment that would otherwise look like a valid
    # reading -- 0x22 is neither 0x01 nor 0x02).
    continuity = []  # list of (value, passed) tuples
    i = 0
    while i <= len(tail) - 4:
        if tail[i] == 0x16 and tail[i + 3] in (0x01, 0x02):
            continuity.append((tail[i + 1] / 1000.0, tail[i + 3] == 0x01))
            i += 4
        else:
            i += 1

    # Single full-precision reading ("Sensitive I"-style Earth Continuity):
    # 0x11 tag, then a 16-bit LE value whose high byte is 0xc0-0xff (every
    # real example has landed in that exponent-3 range, same rescale math
    # as insulation/load/touch below). No confirmed failing example of this
    # specific pattern yet, so it's always treated as passed.
    idx = tail.find(b'\x11')
    while idx != -1 and idx + 3 <= len(tail):
        if 0xc0 <= tail[idx + 2] <= 0xff:
            continuity.append((legacy_rescale(struct.unpack('<H', tail[idx + 1:idx + 3])[0]), True))
            break
        idx = tail.find(b'\x11', idx + 1)

    # Insulation: 0x20, 2 filler bytes, value (16-bit LE), 0x21. That exact
    # 6-byte shape reliably distinguishes it from an unrelated 0x20 byte
    # that can turn up in leftover checklist-internal bytes.
    insulation = None
    polarity = None
    anchor = None
    for i in range(len(tail) - 6):
        if tail[i] == 0x20 and tail[i + 5] == 0x21:
            anchor = i
    if anchor is not None:
        insulation = legacy_rescale(struct.unpack('<H', tail[anchor + 3:anchor + 5])[0])
        marker = tail[anchor + 6:anchor + 8]
        if marker == b'\x91\x01':
            polarity = True
        elif marker == b'\x91\x03':
            polarity = False

    # Load + touch current pair: 0x92 ? 0x49 0x00 0x96 <load> 0x00 0x40 <touch>
    load = touch = None
    for i in range(len(tail) - 11):
        if tail[i] == 0x92 and tail[i + 2] == 0x49 and tail[i + 3] == 0x00 and tail[i + 4] == 0x96:
            load = legacy_rescale(struct.unpack('<H', tail[i + 5:i + 7])[0])
            j = i + 7
            if len(tail) - j >= 4 and tail[j] == 0x00 and tail[j + 1] == 0x40:
                touch = legacy_rescale(struct.unpack('<H', tail[j + 2:j + 4])[0])
            break

    # Touch current on its own, no load (e.g. Sensitive I): same 0x00 0x40
    # prefix. Search backwards from the end and require the value's high
    # byte to be 0xc0-0xff (every genuine reading has been), since generic
    # per-record filler bytes can also contain a 0x00 0x40 pair that isn't
    # a real reading -- rejecting on a failed check and continuing to
    # search earlier occurrences handles both a filler-only tail (no valid
    # match found at all) and a filler-then-real-reading tail (skips past
    # the filler to find the real one). Only used when the load+touch block
    # above wasn't found, so a real pair is never double-counted.
    if load is None and touch is None:
        search_end = len(tail)
        while True:
            idx = tail.rfind(b'\x00\x40', 0, search_end)
            if idx == -1 or idx + 4 > len(tail):
                break
            if 0xc0 <= tail[idx + 3] <= 0xff:
                touch = legacy_rescale(struct.unpack('<H', tail[idx + 2:idx + 4])[0])
                break
            search_end = idx + 1

    # Polarity marker: 0x91 0x01 = pass, 0x91 0x03 = fail -- confirmed via a
    # same-asset retest (failed at 20:34, passed at 21:01, 0x91 0x03 on the
    # first, 0x91 0x01 on the second). Not always immediately after the
    # insulation anchor (e.g. it can follow the load/touch block instead),
    # so also checked for anywhere in the tail if not already found.
    if polarity is None:
        if b'\x91\x01' in tail:
            polarity = True
        elif b'\x91\x03' in tail:
            polarity = False

    return {'continuity': continuity, 'insulation': insulation,
            'load': load, 'touch': touch, 'polarity': polarity}


def parse_apollo_record(rec):
    fields = parse_text_fields(rec)
    if fields is None:
        return None
    electrical = parse_electrical(rec, fields['description_start'])
    # Aborted-test detection: the manufactured fail samples showed that an
    # aborted Apollo test is NOT a noticeably shorter record (padding keeps
    # the overall size normal) -- it's recognized by the absence of *any*
    # genuine reading, not a suite-specific required field (see
    # parse_electrical's docstring for why that was fragile).
    aborted = not (electrical['continuity'] or electrical['insulation'] is not None
                   or electrical['load'] is not None or electrical['touch'] is not None)
    fields['electrical'] = {} if aborted else electrical
    fields['aborted'] = aborted
    return fields


# ---------------------------------------------------------------------------
# Legacy record construction
# ---------------------------------------------------------------------------

def build_legacy_record(fields, meter_serial, when):
    sub = []

    asset_id = fields['seqid']
    sub.append(struct.pack(
        '>B16s4B2s16s16s11s10s11s',
        0x11,  # Visual Pass v2 -- Apollo doesn't expose a visual fail signal we trust
        pack_str(asset_id, 16),
        when.tm_hour, when.tm_min, when.tm_mday, when.tm_mon,
        struct.pack('>H', when.tm_year),
        pack_str(fields['site'], 16),
        pack_str(fields['location'], 16),
        pack_str(fields['tester'], 11),
        pack_str('', 10),   # testcode1 -- no Apollo equivalent found
        pack_str('', 11),   # testcode2 -- no Apollo equivalent found
    ))

    sub.append(struct.pack('>B11s3B', 0xfe, pack_str(meter_serial, 11), 0, 0, 0))
    sub.append(struct.pack('>B3B', 0xe1, 0, 1, 12))

    if fields['aborted']:
        sub.append(struct.pack('>B', 0xf1))  # Overall Fail
    else:
        # parse_electrical() already decoded these to real float values
        # (ohms/MOhm/amps/mA), so no legacy_rescale() call is needed here --
        # only re-encoding into the legacy halfword format.
        elec = fields['electrical']
        for value, passed in elec.get('continuity', []):
            sub.append(struct.pack('>BBBH', 0xf2, 1, 1 if passed else 0, legacy_encode(value)))
        if elec.get('insulation') is not None:
            sub.append(struct.pack('>BBH', 0xf3, 1, legacy_encode(elec['insulation'])))
        if elec.get('load') is not None and elec.get('touch') is not None:
            sub.append(struct.pack('>BBHH', 0xf6, 1,
                                    legacy_encode(elec['touch']), legacy_encode(elec['load'])))
        elif elec.get('touch') is not None:
            # Sensitive I has touch current but no load current, so the F6
            # leakage+load pair (which requires both) doesn't fit; use the
            # single-value current test instead (F4 Substitute Leakage v2).
            sub.append(struct.pack('>BBH', 0xf4, 1, legacy_encode(elec['touch'])))
        if elec.get('polarity') is True:
            sub.append(struct.pack('>B', 0xf9))  # Polarity Pass
        elif elec.get('polarity') is False:
            sub.append(struct.pack('>B', 0xfa))  # Polarity Fail

    # mapping values per SSSUserDataMappingTest.mappings: 1=Asset
    # Description, 0=Notes, 3=Make, 4=Model -- must match what's actually
    # placed in FB's line1-4 below, since this tells the importer how to
    # interpret each line.
    sub.append(struct.pack('>B4B', 0xe0, 1, 0, 3, 4))
    sub.append(struct.pack(
        '>B21s21s21s21s', 0xfb,
        pack_str(fields['description'], 21), pack_str(fields['notes'], 21),
        pack_str(fields['make'], 21), pack_str(fields['model'], 21),
    ))
    sub.append(struct.pack('>B', 0xff))

    payload = b''.join(sub)
    checksum = sum(payload) & 0xffff
    header = struct.pack('>HHH', len(payload), 0, checksum)
    return header + payload


def legacy_rescale(raw_le_halfword):
    v = raw_le_halfword
    return (10 ** -(v >> 14)) * (v & 0x3fff)


def extract_meter_serial(data, default='UNKNOWN'):
    """Apollo stores the meter model + serial once, in a small file-level
    header before the first '\\xff\\x55' record marker (e.g. "Apollo 500
    Plus" / "48R-0034") -- unlike the legacy format, which repeats the
    serial number on every single record. The serial is the last printable
    run in that header region."""
    first_marker = data.find(b'\xff\x55')
    header = data[:first_marker] if first_marker != -1 else data[:64]
    runs = [m.group().decode('latin-1') for m in PRINTABLE_RUN.finditer(header)]
    return runs[-1] if runs else default


def load_test_dates(csv_path):
    """Companion CSV export (Asset ID + 'Last Full Test Date' in DD/MM/YYYY),
    used only as a fallback for the rare record whose native timestamp
    (see 'when' in parse_text_fields) fails its sanity check -- the .gar
    file's own per-record timestamp is the primary date source and is both
    more precise (down to the second) and doesn't require this CSV at all."""
    dates = {}
    with open(csv_path, newline='') as f:
        for row in csv.DictReader(f):
            asset_id = (row.get('Asset ID') or '').strip()
            date_str = (row.get('Last Full Test Date') or '').strip()
            if not asset_id or not date_str:
                continue
            try:
                dates[asset_id] = time.strptime(date_str, '%d/%m/%Y')
            except ValueError:
                continue
    return dates


def convert(gar_path, out_path, meter_serial=None, csv_path=None):
    data = extract_sss_bytes(gar_path)
    if meter_serial is None:
        meter_serial = extract_meter_serial(data)
    fallback_when = time.localtime(os.path.getmtime(gar_path))
    test_dates = load_test_dates(csv_path) if csv_path else {}
    records = find_apollo_records(data)
    out = bytearray()
    converted = 0
    skipped = 0
    dated_from_apollo = 0
    dated_from_csv = 0
    for rec in records:
        fields = parse_apollo_record(rec)
        if fields is None:
            skipped += 1
            continue
        when = fields.get('when')
        if when is not None:
            dated_from_apollo += 1
        else:
            when = test_dates.get(fields['seqid'])
            if when is not None:
                dated_from_csv += 1
            else:
                when = fallback_when
        out += build_legacy_record(fields, meter_serial, when)
        converted += 1
    with open(out_path, 'wb') as f:
        f.write(out)
    print('Converted %d record(s) (%d dated from the .gar itself, %d from CSV), '
          'skipped %d unparseable chunk(s), meter serial %r -> %s' %
          (converted, dated_from_apollo, dated_from_csv, skipped, meter_serial, out_path))


def main():
    if len(sys.argv) < 2:
        print('usage: %s <input.gar> [output.sss] [dates.csv]' % sys.argv[0], file=sys.stderr)
        sys.exit(2)
    gar_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else gar_path.rsplit('.', 1)[0] + '_legacy.sss'
    csv_path = sys.argv[3] if len(sys.argv) > 3 else None
    convert(gar_path, out_path, csv_path=csv_path)


if __name__ == '__main__':
    main()

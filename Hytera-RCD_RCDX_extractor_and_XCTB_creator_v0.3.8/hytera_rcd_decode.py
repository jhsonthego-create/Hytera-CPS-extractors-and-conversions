#!/usr/bin/env python3
"""Read-only decoder for legacy HYTERARCDB radio codeplugs (NOT RCDX).

Exports channel, zone, contact, group, scan, roam tables with their actual
section mappings and source offsets. Never modifies the input.
No external Python dependencies.

Parser references: https://github.com/yl3im/hyrps/tree/master/src/codeplug
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import re
import struct
from pathlib import Path

SIGNATURE = 'HYTERARCDB'.encode('utf-16le')
SECTIONS = {
    0x23: 'zone-member-pointers', 0x24: 'zones', 0x26: 'digital-channels',
    0x27: 'analog-channels', 0x2a: 'dmr-contacts',
    0x2b: 'rx-group-members', 0x6c: 'rx-group-names',
    0x4d: 'scan-members', 0x6d: 'scan-names',
    0x79: 'roam-members', 0x7a: 'roam-names',
}


def u16(buf, offset):
    return struct.unpack_from('<H', buf, offset)[0]


def u32(buf, offset):
    return struct.unpack_from('<I', buf, offset)[0]


def utf16(buf, offset, n=32):
    return buf[offset:offset+n].decode('utf-16le', errors='replace').split('\0', 1)[0].strip()


def csvwrite(path, rows, columns=None):
    rows = list(rows)
    if columns is None:
        columns = list(dict.fromkeys(k for row in rows for k in row))
    with path.open('w', encoding='utf-8', newline='') as fh:
        writer = csv.DictWriter(fh, fieldnames=columns, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)


class Section:
    def __init__(self, b, off):
        self.b = b
        self.off = off
        self.kind, rawcap, self.count, magic, self.unk, self.data_size, end_size = struct.unpack_from('<HHHIIII', b, off)
        self.capacity = rawcap & 0x0fff
        self.flags = rawcap >> 12
        if magic != 32 or end_size != self.data_size + 22 or not 0 < self.capacity <= 4095:
            raise ValueError('Invalid section header')
        if not 0 <= self.count <= self.capacity or self.data_size % self.capacity:
            raise ValueError('Invalid section capacity/count/record alignment')
        self.record_size = self.data_size // self.capacity
        self.data_start = off + 22
        self.mapping_start = self.data_start + self.data_size
        self.end = self.mapping_start + self.capacity * 6
        if self.end > len(b):
            raise ValueError('Section extends beyond end of file')
        self.mappings = []
        for i in range(self.capacity):
            phys, offset = struct.unpack_from('<HI', b, self.mapping_start + i*6)
            self.mappings.append((phys, offset))
        for j, (phys, ofs) in enumerate(self.mappings[:self.count]):
            if phys >= self.capacity or ofs >= self.data_size or ofs % self.record_size:
                raise ValueError('Active section mapping out of bounds')

    def pos(self, logical):
        """Logical is one-based, as are RCD channel references."""
        if not 1 <= logical <= self.count:
            raise IndexError(f'section {self.kind:02x} logical index {logical} (count={self.count})')
        phys, offset = self.mappings[logical-1]
        return self.data_start + offset

    def mapping(self, logical):
        return self.mappings[logical-1]

    def details(self):
        return dict(section=SECTIONS.get(self.kind, f'0x{self.kind:02x}'), section_id=f'0x{self.kind:02X}',
                    header_offset=self.off, active_count=self.count, capacity=self.capacity,
                    record_size=self.record_size, flags=self.flags, raw_bytes_per_record=self.record_size)


def discover_sections(b):
    # A section header is identified by its 0x20 constant, valid lengths,
    # aligned mapping entries, and non-overlapping placement.
    # The sections can move between older Hytera CPS/RCD versions.
    result = {}
    marker = struct.pack('<I', 32)
    start = 0
    while True:
        match = b.find(marker, start)
        if match < 0:
            break
        start = match + 1
        off = match - 6
        if off < 0:
            continue
        try:
            sec = Section(b, off)
        except (ValueError, struct.error, ZeroDivisionError):
            continue
        if sec.kind in SECTIONS and sec.kind not in result:
            result[sec.kind] = sec
    return result


def tone(word):
    # Ctcss::load: 12-bit magnitude + 2 high-bit tone kind.
    typ = (word >> 14) & 3
    val = word & 0x0fff
    if typ == 0:
        return {'kind':'none', 'value':'', 'polarity':'', 'raw_word':f'0x{word:04X}', 'reserved_flags': f'0x{word & 0x3000:04X}'}
    if typ == 1:
        return {'kind':'CTCSS', 'value':f'{val/10:.1f}', 'polarity':'', 'raw_word':f'0x{word:04X}', 'reserved_flags': f'0x{word & 0x3000:04X}'}
    return {'kind':'DCS', 'value':format(val,'03o'), 'polarity':'inverted' if typ == 3 else 'normal',
            'raw_word':f'0x{word:04X}', 'reserved_flags': f'0x{word & 0x3000:04X}'}


def read_pointer(b, off, digital, analog, contacts=None):
    idx, kind, flags = struct.unpack_from('<HBB', b, off)
    if idx == 65535:
        return dict(kind='selected', source_index=idx, name='<Selected>', resolved=True, flags_hex=f'0x{flags:02X}')
    if contacts is not None:
        value = contacts.get(idx)
        return dict(kind='dmr_contact', source_index=idx, name=value['name'] if value else '',
                    contact_id=value['dmr_id'] if value else '', resolved=bool(value),flags_hex=f'0x{flags:02X}')
    data = digital if kind == 0 else analog if kind == 1 else None
    value = data.get(idx) if data else None
    return dict(kind={0:'digital',1:'analog'}.get(kind, f'unknown_{kind}'),source_index=idx,
                name=value['name'] if value else '',resolved=bool(value),flags_hex=f'0x{flags:02X}')


def read_members(b, section, list_index, digital, analog, contact_lookup=None):
    """Decode mapped channel pointers, never assuming sequential storage offsets."""
    pos = section.pos(list_index)
    marker, capacity, count, data_bytes, mappings_offset = struct.unpack_from('<HHHII', b, pos)
    if count > capacity or mappings_offset < 14+data_bytes or mappings_offset+6*count > section.record_size:
        raise ValueError(f'Malformed member-pointer section 0x{section.kind:02X} list {list_index}')
    members = []
    for j in range(count):
        map_idx, data_offset = struct.unpack_from('<HI', b, pos + mappings_offset + j*6)
        if data_offset + 4 > data_bytes:
            raise ValueError('Member pointer offset exceeds allocated data')
        ptr = read_pointer(b, pos + 14 + data_offset, digital, analog, contacts=contact_lookup)
        members.append(dict(position=j+1, mapping_index=map_idx,
                            pointer_offset=pos+14+data_offset, **ptr))
    return members, dict(inner_count=count, inner_capacity=capacity, inner_data_size=data_bytes, inner_marker=marker)


def decode_source(b, source_name):
    if not b.startswith(SIGNATURE):
        raise ValueError('Not a legacy HYTERARCDB .rcd file. Encrypted RCDX is not supported.')
    secs = discover_sections(b)
    missing = [k for k in SECTIONS if k not in secs]
    if missing:
        raise ValueError('Missing required section(s): ' + ', '.join(f'0x{k:02X}' for k in missing))
    if secs[0x26].record_size != 76 or secs[0x27].record_size != 76 or secs[0x2a].record_size != 48:
        raise ValueError('Unknown channel/contact layout; refusing to guess field offsets')
    warnings = []
    channels, digital, analog = [], {}, {}
    for kind, key, cmap in [('digital',0x26,digital),('analog',0x27,analog)]:
        sec = secs[key]
        for logical in range(1,sec.count+1):
            off = sec.pos(logical)
            physical, stored_offset = sec.mapping(logical)
            name = utf16(b,off)
            rx,tx = u32(b,off+36),u32(b,off+40)
            if not name or not (100_000_000<=rx<=999_999_999 and 100_000_000<=tx<=999_999_999):
                warnings.append(f'Unexpected {kind} channel {logical} name/frequencies at byte {off}')
            options = b[off+33]
            r = dict(kind=kind, logical_index=logical, physical_slot=physical+1, source_offset=off,
                     name=name, rx_hz=rx, tx_hz=tx, rx_mhz=f'{rx/1e6:.6f}',tx_mhz=f'{tx/1e6:.6f}',
                     rx_only=bool(options & 1), power='low' if options & 4 else 'high',
                     channel_type_raw=b[off+32], channel_options_hex=f'0x{options:02X}')
            if kind == 'analog':
                rt, tt = tone(u16(b,off+44)),tone(u16(b,off+46))
                r.update(rx_tone_type=rt['kind'],rx_tone=rt['value'],rx_dcs_polarity=rt['polarity'],
                         rx_tone_raw=rt['raw_word'],rx_tone_reserved=rt['reserved_flags'],
                         tx_tone_type=tt['kind'],tx_tone=tt['value'],tx_dcs_polarity=tt['polarity'],
                         tx_tone_raw=tt['raw_word'],tx_tone_reserved=tt['reserved_flags'],
                         rx_squelch_mode_raw=b[off+48], monitor_squelch_mode_raw=b[off+49],
                         channel_change_squelch_mode_raw=b[off+50], carrier_squelch_level_raw=b[off+52],
                         tx_admit_raw=b[off+53], tx_timeout_raw=b[off+54],
                         tot_prealert_raw=b[off+55],tot_rekey_raw=b[off+56],tot_reset_raw=b[off+57],
                         auto_reset_mode_raw=b[off+58],auto_reset_time_raw=b[off+59],
                         signalling_type_raw=b[off+61],emergency_system_index=b[off+63],
                         emergency_flags_hex=f'0x{b[off+64]:02X}',scan_list_index=b[off+65],
                         auto_start_scan=bool(b[off+66]&1),emphasis=bool(b[off+66]&0x10),
                         compandor=bool(b[off+66]&0x20),scrambler=bool(b[off+66]&0x40),
                         vox=bool(b[off+67]&0x80))
            else:
                dc_flags=b[off+49]
                sl_idx=b[off+56]
                mode=b[off+58]
                sl_type=mode&0x30
                sl_label={0:'none',0x10:'scan',0x20:'roam'}.get(sl_type, f'unknown_{sl_type:02x}')
                slot_value=mode&3
                r.update(color_code=dc_flags&0x0f,priority_interrupt_encode=bool(dc_flags&0x20),
                         priority_interrupt_decode=bool(dc_flags&0x40),
                         timeslot={0:'1',1:'2',3:'pseudo-trunk'}.get(slot_value,f'unknown-{slot_value}'),
                         timeslot_raw=slot_value, tx_contact_index=u16(b,off+50),
                         rx_group_index=u16(b,off+52),emergency_system_index=u16(b,off+54),
                         list_type=sl_label,list_index=sl_idx if sl_label!='none' else 0,
                         auto_start_scan=bool(b[off+57]&1),auto_start_roam=bool(mode&4),
                         ip_multi_site_connect=bool(b[off+57]&0x20),vox=bool(mode&0x40),
                         tx_admit_raw=b[off+44],tx_timeout_raw=b[off+45],
                         tot_prealert_raw=b[off+46],tot_rekey_raw=b[off+47],tot_reset_raw=b[off+48])
            r['raw_record_hex'] = b[off:off+sec.record_size].hex()
            channels.append(r)
            cmap[logical] = r

    # Preserve mapped-out (physically populated but inactive) channel slots.
    residues=[]
    for kind,key in [('digital',0x26),('analog',0x27)]:
        sec=secs[key]
        active_physical={physical for physical,ofs in sec.mappings[:sec.count]}
        for physical in range(sec.capacity):
            if physical in active_physical:
                continue
            off=sec.data_start + physical*sec.record_size
            data=b[off:off+sec.record_size]
            if not any(data):
                continue
            # Only export named, plausible channel-shaped residues.
            nm=utf16(b,off)
            rx,tx=u32(b,off+36),u32(b,off+40)
            if nm and 100_000_000<=rx<=999_999_999 and 100_000_000<=tx<=999_999_999:
                residues.append(dict(kind=kind, physical_slot=physical+1, source_offset=off,name=nm,
                                     rx_mhz=f'{rx/1e6:.6f}',tx_mhz=f'{tx/1e6:.6f}',
                                     status='inactive (not present in active section mapping)',raw_record_hex=data.hex()))

    contacts=[]
    for logical in range(1,secs[0x2a].count+1):
        off=secs[0x2a].pos(logical)
        call_type=b[off+36]
        contacts.append(dict(logical_index=logical,name=utf16(b,off+4),dmr_id=u32(b,off+40),
            call_type={0:'private',1:'group',0x11:'ignore'}.get(call_type,f'unknown_{call_type}'),
            is_reference=bool(b[off+37]),source_offset=off,raw_record_hex=b[off:off+48].hex()))
    contact_lookup={x['logical_index']:x for x in contacts}

    groups=[];group_members=[]
    for li in range(1,secs[0x6c].count+1):
        name=utf16(b,secs[0x6c].pos(li))
        members,_=read_members(b,secs[0x2b],li,digital,analog, contact_lookup=contact_lookup)
        groups.append(dict(index=li,name=name,member_count=len(members)))
        group_members += [dict(group_index=li,group_name=name,**m) for m in members]

    zones=[];zone_members=[]
    for li in range(1,secs[0x24].count+1):
        off=secs[0x24].pos(li)
        name=utf16(b,off)
        members,ptr_header=read_members(b,secs[0x23],li,digital,analog)
        declared=u16(b,off+32)
        if declared!=len(members):
            warnings.append(f'Zone {li}: declared {declared}, pointer section contains {len(members)}')
        zones.append(dict(index=li,name=name,declared_channels=declared,decoded_members=len(members),source_offset=off))
        zone_members += [dict(zone_index=li,zone_name=name,**m) for m in members]

    scans=[];scan_members=[]
    for li in range(1,secs[0x6d].count+1):
        off=secs[0x6d].pos(li); name=utf16(b,off)
        members,_=read_members(b,secs[0x4d],li,digital,analog)
        scans.append(dict(index=li,name=name,member_count=len(members),source_offset=off))
        scan_members += [dict(scan_index=li,scan_name=name,**m) for m in members]

    roams=[];roam_members=[]
    for li in range(1,secs[0x7a].count+1):
        off=secs[0x7a].pos(li); name=utf16(b,off)
        members,_=read_members(b,secs[0x79],li,digital,analog)
        roams.append(dict(index=li,name=name,member_count=len(members),source_offset=off))
        roam_members += [dict(roam_index=li,roam_name=name,**m) for m in members]

    for r in channels:
        if r['kind']=='digital':
            c=contact_lookup.get(r['tx_contact_index'])
            r['tx_contact_name']=c['name'] if c else ''
            r['tx_contact_dmr_id']=c['dmr_id'] if c else ''
            r['rx_group_name']=next((g['name'] for g in groups if g['index']==r['rx_group_index']),'')
            if r['tx_contact_index'] and not c:
                warnings.append(f"Digital {r['logical_index']} TX contact #{r['tx_contact_index']} unresolved")
            if r['list_type'] in ('scan','roam') and r['list_index']:
                names=scans if r['list_type']=='scan' else roams
                r['list_name']=next((x['name'] for x in names if x['index']==r['list_index']),'')
                if not r['list_name']:
                    warnings.append(f"Digital {r['logical_index']} {r['list_type']} list #{r['list_index']} unresolved")
        else:
            r['scan_list_name']=next((s['name'] for s in scans if s['index']==r['scan_list_index']),'')

    rows={'channels.csv':channels,'digital-channels.csv':[c for c in channels if c['kind']=='digital'],
          'analog-channels.csv':[c for c in channels if c['kind']=='analog'],
          'inactive-channel-records.csv':residues,
          'dmr-contacts.csv':contacts,'rx-groups.csv':groups,'rx-group-members.csv':group_members,
          'zones.csv':zones,'zone-members.csv':zone_members,
          'scan-lists.csv':scans,'scan-members.csv':scan_members,
          'roam-lists.csv':roams,'roam-members.csv':roam_members,
          'sections.csv':[s.details() for s in secs.values()]}
    for filename,items in [('zone-members.csv',zone_members),('scan-members.csv',scan_members),
                           ('roam-members.csv',roam_members),('rx-group-members.csv',group_members)]:
        unresolved=[m for m in items if not m['resolved']]
        if unresolved:
            warnings.append(f'{filename}: {len(unresolved)} unresolved pointer(s)')

    strings=[]
    for enc,pattern,codec in [('utf16le', rb'(?:[\x20-\x7e]\x00){4,}','utf-16le'),
                              ('ascii', rb'[\x20-\x7e]{4,}', 'ascii')]:
        for m in re.finditer(pattern,b):
            strings.append(dict(offset=m.start(),encoding=enc,text=m.group().decode(codec)))
    rows['strings.csv']=sorted(strings,key=lambda s:s['offset'])

    counts=dict(active_channels=len(channels),analog=sum(r['kind']=='analog' for r in channels),
                digital=sum(r['kind']=='digital' for r in channels),inactive_named_channel_records=len(residues),
                contacts=len(contacts),rx_groups=len(groups),rx_group_members=len(group_members),
                zones=len(zones),zone_members=len(zone_members),scan_lists=len(scans),
                scan_members=len(scan_members),roam_lists=len(roams),roam_members=len(roam_members))
    report=dict(source=source_name, bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),
                format='Legacy Hytera HYTERARCDB (not encrypted RCDX)',counts=counts,
                cross_references_valid=not warnings, warnings=warnings,
                notes=['Records decoded in logical section-mapping order, not raw physical-slot order.',
                       'Physical records outside active mapping exported separately as inactive residues.',
                       'Selected-channel sentinel (0xFFFF) retained in scan/roam lists.',
                       'Unknown radio settings remain available in per-channel raw_record_hex.',
                       'Read-only tool. Report is private radio programming data.'],
                decoded_sections=sorted([s.details() for s in secs.values()],key=lambda s:s['header_offset']))
    return rows, report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file',type=Path,help='Input legacy .rcd file')
    parser.add_argument('--outdir',type=Path,default=Path('rcd-decoded'))
    parser.add_argument('--no-hex',action='store_true',help='Skip complete 16-byte hex inventory CSV')
    args=parser.parse_args()
    try:
        b=args.file.read_bytes()
        rows,report=decode_source(b,args.file.name)
    except (OSError,ValueError,IndexError,struct.error) as err:
        parser.exit(2,f'ERROR: {err}\n')
    args.outdir.mkdir(parents=True,exist_ok=True)
    for fname,values in rows.items():
        csvwrite(args.outdir/fname,values)
    if not args.no_hex:
        with (args.outdir/'hex-inventory.csv').open('w',newline='',encoding='utf-8') as fh:
            w=csv.writer(fh);w.writerow(['offset','hex_16_bytes'])
            for off in range(0,len(b),16):
                w.writerow([off,b[off:off+16].hex()])
    (args.outdir/'report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report['counts'],indent=2))
    if report['warnings']:
        print('WARNINGS:', *report['warnings'],sep='\n - ')
    print('Output:',args.outdir)


if __name__=='__main__':
    main()

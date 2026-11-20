#!/usr/bin/env python3
"""TEST-ONLY Hytera RCDX decoded channels/contacts/zones -> Motorola CPS2 XCTB.

Decodes a user-provided Hytera RCDX directly. No Excel exports or separate
extractor run required. TX contacts, timeslots and real zone ordering come from RCDX.
Scan/roam member lists are recovered; oversized scan lists are split rather
than silently truncated. Empty receive groups are not invented.

The Motorola destination is a model-specific user-supplied existing CPS2 XCTB
(template), NOT a generic file constructed from scratch. Original template
personality/contact/zone records remain unchanged. The generated archive is
REQUIRES validation in Motorola CPS GUI/hardware and MUST NOT be programmed as-is.

Requires Python 3.9+, cryptography, and lxml. Keep hytera_extract.py and hytera_codec.py alongside.
"""
import argparse,base64,collections,copy,csv,decimal,difflib,gzip,hashlib,json,os,struct,sys,uuid,zlib
import xml.etree.ElementTree as ET
from pathlib import Path
def verify_rcdx(blob):
    if not blob.startswith('HYTERARCDB'.encode('utf-16le')) or len(blob)<256:
        raise ValueError('Not a valid HYTERARCDB file')
    declared=struct.unpack_from('<I',blob,24)[0]
    if declared!=len(blob):raise ValueError('RCDX declared length mismatch')
    def wide(data):return data.decode('utf-16le','replace').split('\0')[0].strip()
    return {'signature':'HYTERARCDB','length_bytes':len(blob),
            'model':wide(blob[68:100]),'cps_version':wide(blob[100:132])}
def sha(b): return hashlib.sha256(b).hexdigest()
from hytera_codec import decrypt as decrypt_rcdx
from hytera_extract import parse_plaintext
import re, xml.parsers.expat
from lxml import etree as LET

XS='{http://www.w3.org/2001/XMLSchema-instance}type'
ENT_NS='http://schemas.datacontract.org/2004/07/Motorola.CommonCPS.Server.EntityModel'
I_NS='http://www.w3.org/2001/XMLSchema-instance'
Z_NS='http://schemas.microsoft.com/2003/10/Serialization/'
ET.register_namespace('',ENT_NS);ET.register_namespace('i',I_NS);ET.register_namespace('z',Z_NS)
SEED=b'627842'
TONE_CODE={'288.5':'STR_138','349.0':'STR_111','368.5':'STR_112','553.9':'STR_150',
           '584.8':'STR_151','617.4':'STR_152','651.9':'STR_153','688.3':'STR_154',
           '726.8':'STR_155','767.4':'STR_156','810.2':'STR_157','855.5':'STR_158','903.2':'STR_159'}
TPL_CODE={
    '67.0': 'STR_XZ',
    '69.3': 'STR_WZ',
    '71.9': 'STR_XA',
    '74.4': 'STR_WA',
    '77.0': 'STR_XB',
    '79.7': 'STR_WB',
    '82.5': 'STR_YZ',
    '85.4': 'STR_YA',
    '88.5': 'STR_YB',
    '91.5': 'STR_ZZ',
    '94.8': 'STR_ZA',
    '97.4': 'STR_ZB',
    '100.0': 'STR_1Z',
    '103.5': 'STR_1A',
    '107.2': 'STR_1B',
    '110.9': 'STR_2Z',
    '114.8': 'STR_2A',
    '118.8': 'STR_2B',
    '123.0': 'STR_3Z',
    '127.3': 'STR_3A',
    '131.8': 'STR_3B',
    '136.5': 'STR_4Z',
    '141.3': 'STR_4A',
    '146.2': 'STR_4B',
    '151.4': 'STR_5Z',
    '156.7': 'STR_5A',
    '162.2': 'STR_5B',
    '167.9': 'STR_6Z',
    '173.8': 'STR_6A',
    '179.9': 'STR_6B',
    '186.2': 'STR_7Z',
    '192.8': 'STR_7A',
    '203.5': 'STR_M1',
    '206.5': 'STR_8Z',
    '210.7': 'STR_M2',
    '218.1': 'STR_M3',
    '225.7': 'STR_M4',
    '229.1': 'STR_9Z',
    '233.6': 'STR_M5',
    '241.8': 'STR_M6',
    '250.3': 'STR_M7',
}

def tone_key(value):return str(decimal.Decimal(str(value)).quantize(decimal.Decimal('0.1')))
def freq(value):return format(decimal.Decimal(str(value)).normalize(),'f')
def h(b):return hashlib.sha256(b).digest()
def xor(a,b):return bytes(x^y for x,y in zip(a,b))
def aes_key(iv):
    s=h(SEED);return h(xor(iv,xor(s[:16],s[16:])))
def dec_archive(blob):
    from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
    start=blob.find(b'{\r\n  "version"')
    if start<4:raise ValueError('Unknown XCTB layout')
    length=struct.unpack_from('<I',blob,start-4)[0];end=start+length
    if end>len(blob):raise ValueError('Bad XCTB header length')
    hdr=json.loads(blob[start:end].decode('utf8'))
    if hdr.get('type')!='xctb' or hdr.get('protect')!='d':raise ValueError('Only default-protected .xctb templates supported')
    if hdr.get('dataModelVersion',{}).get('Version')!='2.153.50':
        raise ValueError('Only independently tested dataModelVersion 2.153.50 templates supported')
    iv=base64.b64decode(hdr['stamp'],validate=True)
    ct=blob[end:]
    if len(iv)!=16 or len(ct)%16:raise ValueError('Invalid XCTB IV/ciphertext')
    c=Cipher(algorithms.AES(aes_key(iv)),modes.CBC(iv)).decryptor();padded=c.update(ct)+c.finalize()
    pad=padded[-1]
    if not 1<=pad<=16 or padded[-pad:]!=bytes([pad])*pad:raise ValueError('AES padding check failed')
    z=gzip.decompress(padded[:-pad]);n=struct.unpack_from('<I',z)[0]
    inner=json.loads(z[4:4+n].decode('utf8'));xml=z[4+n:]
    if base64.b64encode(h(xml)).decode()!=inner['checksum']:raise ValueError('Inner SHA256 checksum failed')
    root=ET.fromstring(xml)
    if root.tag.rsplit('}',1)[-1]!='MatrixRadio':raise ValueError('Not MatrixRadio XML')
    return blob[:start-4],hdr,inner,root,xml

def pack_archive(prefix,hdr,inner,radio):
    from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
    xml=radio if isinstance(radio,bytes) else ET.tostring(radio,encoding='utf-8',xml_declaration=False)
    inner=dict(inner);inner['checksum']=base64.b64encode(h(xml)).decode()
    js=json.dumps(inner,ensure_ascii=False,separators=(',',':')).encode()
    z=struct.pack('<I',len(js))+js+xml
    gz=gzip.compress(z,mtime=0)
    iv=os.urandom(16);hdr=dict(hdr);hdr['stamp']=base64.b64encode(iv).decode()
    raw=(json.dumps(hdr,ensure_ascii=False,indent=2).replace('\n','\r\n')+'\r\n').encode('utf8')
    if not raw.startswith(b'{\r\n  "version"'):raise ValueError('Header serializer changed first key')
    pad=16-len(gz)%16;plain=gz+bytes([pad])*pad
    enc=Cipher(algorithms.AES(aes_key(iv)),modes.CBC(iv)).encryptor()
    ct=enc.update(plain)+enc.finalize()
    return prefix+struct.pack('<I',len(raw))+raw+ct

def is_record(x):return x.get(XS)=='Record'
def recs(g):return [x for x in g if is_record(x)]
def field(x,k):return next((a for a in x if a.get('Name')==k and a.get(XS) in ('DBField','DBRefField')),None)
def get(x,k):
    e=field(x,k);return e.get('Value') if e is not None else None
def setf(x,k,value):
    e=field(x,k)
    if e is None:raise ValueError(f'Expected field {k!r} missing in cloned Motorola record')
    e.set('Value',str(value))
def find_child(x,name):
    return next((a for a in x if a.get('Name')==name),None)
def newid():return str(uuid.uuid4())
def clone(rec,index):
    new=copy.deepcopy(rec)
    new.set('Name',str(index))
    for x in new.iter():
        if is_record(x):x.set('UUID',newid())
    return new

def rowdict(rows):
    header=rows[0]
    out=[]
    for row in rows[1:]:
        if not row or not row[0]:continue
        used=collections.Counter();fields={}
        for i,k in enumerate(header):
            if not k:continue
            used[k]+=1
            key=k if used[k]==1 else k+'__'+str(used[k])
            fields[key]=row[i] if i<len(row) else ''
        out.append(fields)
    return out

def existing_contact_by_call(groups):
    m={}
    for r in recs(groups['PCRContacts']):
        group=find_child(r,'DigitalCalls')
        if group is None:continue
        for c in recs(group):
            call_id=get(c,'DU_CALLLSTID');call_type=get(c,'DU_CALLTYPE')
            if call_id and call_type:m[(call_id,call_type)]=r.get('UUID')
    return m

def safe_alias(a,max_chars=16):
    # Preserve original in report, truncate only if destination radio limits.
    return a[:max_chars]

def register_contacts(groups,dmr,twotone,audit,warnings):
    cg=groups['PCRContacts'];existing=existing_contact_by_call(groups)
    # Explicitly select a contact with only a DigitalCalls item
    digital_proto=next(x for x in recs(cg) if find_child(x,'DigitalCalls') is not None and
                       len(recs(find_child(x,'DigitalCalls')))==1 and
                       all(child.get('Name')=='DigitalCalls' or not recs(child) for child in x if child.get(XS)=='RefSet'))
    qc_proto=next(x for x in recs(cg) if find_child(x,'QuikCallIICalls') is not None and
                  len(recs(find_child(x,'QuikCallIICalls')))==1 and
                  find_child(x,'DigitalCalls') is None)
    codeg=groups['QuikCallIISystems'];sproto=recs(codeg)[0]
    inserted=0;reused=0;systems_new=0;added_twotone=0
    for d in dmr:
        ident=str(int(d['Call ID']))
        ctype=d['Call Type'].lower().strip()
        tt='GRPCALL' if ctype=='group call' else 'PRIVCALL' if ctype=='private call' else 'ALLCALL' if ctype=='all call' else None
        if not tt:raise ValueError('Unknown DMR call type '+repr(d['Call Type']))
        key=(ident,tt)
        if key in existing:
            target=existing[key];reused+=1;status='REUSED_MATCHING_TYPE_ID'
        else:
            new=clone(digital_proto,len(recs(cg)))
            setf(new,'ContactName',safe_alias(d['Call Alias'],32))
            call=recs(find_child(new,'DigitalCalls'))[0]
            setf(call,'DU_CALLLSTID',ident);setf(call,'DU_CALLTYPE',tt)
            cg.append(new);target=new.get('UUID');existing[key]=target;inserted+=1;status='CREATED'
        audit.append({'type':'DMR_CONTACT','source':d['Call Alias'],'detail':ident,'target':target,'status':status})
    for d in twotone:
        fmt=d['Encode Format'].strip().lower();a=tone_key(d['1st Tone Frequency [Hz]']);b=tone_key(d['2nd Tone Frequency [Hz]'])
        if a not in TONE_CODE or (fmt=='two tone' and b not in TONE_CODE):raise ValueError('Missing independently verified Motorola Quick Call II code for '+a+'/'+b)
        # For a long tone, match an EXISTING Motorola system's long-C frequency.
        if fmt=='long tone':
            matches=[sys for sys in recs(codeg) if get(sys,'QCIISYS_FORMATTYPE')=='CALLFMT_AB_LONG_C' and get(sys,'QCIISYS_TONECRF') and tone_key(get(sys,'QCIISYS_TONECRF'))==a]
            if len(matches)!=1:raise ValueError(f'Long-tone {a} Hz has no unique verified existing Motorola AB/Long C system; refusing to invent filler tones')
            system_ref=matches[0].get('UUID');call_fmt='LONG_TONE';status='EXISTING_MATCH_LONG_C'
        elif fmt=='two tone':
            sy=clone(sproto,len(recs(codeg)))
            setf(sy,'QCIISYS_QCIISYSALIAS',safe_alias(d['Call Alias'],16))
            setf(sy,'QCIISYS_FORMATTYPE','CALLFMT_AB')
            setf(sy,'QCIISYS_TONEARF',a);setf(sy,'QCIISYS_CODEA',TONE_CODE[a])
            setf(sy,'QCIISYS_TONEBRF',b);setf(sy,'QCIISYS_CODEB',TONE_CODE[b])
            codeg.append(sy);system_ref=sy.get('UUID');call_fmt='TWO_TONE';systems_new+=1;status='NEW_AB_SYSTEM'
        else:raise ValueError('Unsupported 2-tone format '+repr(d['Encode Format']))
        c=clone(qc_proto,len(recs(cg)));setf(c,'ContactName',safe_alias(d['Call Alias'],32))
        call=recs(find_child(c,'QuikCallIICalls'))[0]
        setf(call,'QU_QCIISYS',system_ref);setf(call,'QU_CALLFORMAT',call_fmt)
        setf(call,'QU_TONEATXFRE',a);setf(call,'QU_CODEA',TONE_CODE[a])
        if fmt=='two tone':setf(call,'QU_TONEBTXFRE',b);setf(call,'QU_CODEB',TONE_CODE[b])
        else:
            # Second tone (1000 Hz on the export) is inactive in LONG_TONE.
            # Retain template's inactive B value; do not treat it as an active tone.
            warnings.append(f'{d["Call Alias"]}: source inactive second tone {b} Hz is not sent for LONG_TONE')
        cg.append(c);added_twotone+=1
        audit.append({'type':'2TONE_CONTACT','source':d['Call Alias'],'detail':f'{fmt} {a} {b}',
                      'target':c.get('UUID'),'status':status})
    return {'digital_contacts_created':inserted,'digital_contacts_reused':reused,
            'two_tone_contacts_created':added_twotone,'two_tone_systems_created':systems_new}

def set_squelch(node,side,mode,tpl,dcs):
    suffix='RX' if side=='RX' else 'TX'
    typfield='CP_XSQCHTY' if side=='RX' else 'CP_TXSQCHTY'
    if mode.upper().strip()=='CTCSS':
        tone=tone_key(tpl)
        if tone not in TPL_CODE:raise ValueError('No verified Motorola TPL enum for '+tone)
        setf(node,typfield,'TPL');setf(node,'CP_RXTPLFREQ' if side=='RX' else 'CP_TXTTPLFREQ',tone)
        setf(node,'CP_RXTPLCODE' if side=='RX' else 'CP_TXTPLCODE',TPL_CODE[tone])
    elif mode.upper().strip()=='CDCSS':
        dcs=str(dcs).zfill(3)
        if not revalidate_dcs(dcs):raise ValueError('Invalid DCS value '+dcs)
        setf(node,typfield,'DPL');setf(node,'CP_RXDPLCD' if side=='RX' else 'CP_TXTDPLCD',dcs)
        setf(node,'CP_RXDPLINV' if side=='RX' else 'CP_TXDPLINV','False')
    elif mode.lower().strip() in ('off','none','csq','carrier'):
        setf(node,typfield,'CSQ')
    else:raise ValueError('Unknown Hytera squelch '+repr(mode))

def revalidate_dcs(x):return len(x)==3 and all(z in '01234567' for z in x)

def import_personalities(groups,digital,analog,audit,warnings,decoded,txcontacts):
    g=groups['ConventionalPersonality'];existing=recs(g)
    digi=next(x for x in existing if (get(x,'CP_PERSTYPE') or '').startswith('DGTL'))
    anlg=next(x for x in existing if (get(x,'CP_PERSTYPE') or '').startswith('ANLG'))
    assignments={'HYTERA DIGITAL':[],'HYTERA ANALOG':[]}
    indexed={}
    # The Excel export has a different row order than the RCDX records.
    # Match by exact untruncated alias + RX/TX rather than positional index.
    from collections import defaultdict
    for k,items in [('DIGITAL',decoded['digital_channels']),('ANALOG',decoded['analog_channels'])]:
        b=defaultdict(list)
        for x in items:b[(x['name'],freq(x['rx_mhz']),freq(x['tx_mhz']))].append(x)
        if len(items)!=len(digital if k=='DIGITAL' else analog):
            raise ValueError(f'Decoded channel count mismatch for {k}')
        if any(len(v)!=1 for v in b.values()):raise ValueError(f'Non-unique RCDX {k} alias/frequency combination')
        indexed[k]=b
    uuid_by_source={}
    warnings.append('Hytera RX-group membership is empty and is not invented; source references remain in the extracted JSON.')
    for kind,items,proto in [('DIGITAL',digital,digi),('ANALOG',analog,anlg)]:
        for d in items:
            alias=d['Channel Alias'];rx=freq(d['Receive Frequency [MHz]']);tx=freq(d['Transmit Frequency [MHz]'])
            key=(alias,rx,tx)
            found=indexed[kind].pop(key,None)
            if found is None:raise ValueError('Decoded channel lookup mismatch '+repr(key))
            source=found[0]
            target=clone(proto,len(recs(g)))
            setf(target,'CP_CNVPERSALIAS',safe_alias(alias))
            setf(target,'CP_RXFREQ',rx);setf(target,'CP_TXFREQ',tx)
            setf(target,'CP_TXPWR','HIGHPWR' if d['Power Level'].lower()=='high' else 'LOWPWR')
            setf(target,'CP_RXONLYEN','True' if d['Rx Only'].lower()=='enable' else 'False')
            setf(target,'CP_RXONLY','True' if d['Rx Only'].lower()=='enable' else 'False')
            setf(target,'CP_TOT',d['Tx Time-out Time [s]'])
            setf(target,'CP_TOTREKEYDELAY',d['TOT Re-key Time [s]'])
            # Hytera Always Allow has no verified identical Motorola CPS enum.
            # Retain the validated destination template's transmit criteria.
            setf(target,'CP_SCNROAMLISTIT','NONE')
            setf(target,'CP_UTOSCANEN','False')
            setf(target,'CP_UKPPERS','NONE')
            setf(target,'CP_TALKAROUNDEN','True' if d.get('Talk Around','').lower()=='enable' else 'False')
            if len(alias)>16:warnings.append(f'{alias}: Motorola alias truncated to 16 chars, full source preserved in CSV/audit')
            if kind=='DIGITAL':
                cc=d['Color Code']
                if not cc.isdigit() or not 0<=int(cc)<=15:raise ValueError('Invalid Color Code '+repr(cc))
                setf(target,'CP_COLORCODE',cc)
                slot=source['timeslot']
                if slot not in ('Slot 1','Slot 2'):raise ValueError(f'Unknown RCDX timeslot {alias}: {slot!r}')
                setf(target,'CP_SLTASSGMNT','SLOT1' if slot=='Slot 1' else 'SLOT2')
                # Hytera calls and Motorola contact references are matched by
                # exact DMR call ID and call TYPE, not by spreadsheet row order.
                calltyp={'Group Call':'GRPCALL','Private Call':'PRIVCALL','All Call':'ALLCALL'}
                if source['tx_contact_index']:
                    callkey=(str(source['tx_contact_call_id']),calltyp[source['tx_contact_call_type']])
                    if callkey not in txcontacts:raise ValueError(f'TX contact missing for {alias}: {callkey}')
                    setf(target,'CP_UKPPERS',txcontacts[callkey])
                else:
                    setf(target,'CP_UKPPERS','NONE')
                setf(target,'CP_TGLISTIT','NONE')
                # Scan/roam assignments are resolved after real decoded lists
                # are created; never point to template lists by coincidence.
            else:
                spac=d['Channel Spacing [KHz]']
                if spac not in ('12.5','25.0','25'):
                    raise ValueError('Unsupported analog channel spacing: '+spac)
                setf(target,'CP_CHNLBWDTH','STR_12PT5KHZ' if spac=='12.5' else 'STR_25KHZ')
                set_squelch(target,'RX',d['Rx CTCSS/CDCSS Type'],d['CTCSS'],d['CDCSS'])
                set_squelch(target,'TX',d['Tx CTCSS/CDCSS Type'],d['CTCSS__2'],d['CDCSS__2'])
                if any(d[t]=='CTCSS' and tone_key(d[k])=='114.8' for t,k in
                       (('Rx CTCSS/CDCSS Type','CTCSS'),('Tx CTCSS/CDCSS Type','CTCSS__2'))):
                    warnings.append(f'{alias}: Motorola 114.8Hz CTCSS code STR_2A taken from supplied Motorola Legacy PL reference; verify in CPS.')
            g.append(target)
            assignments['HYTERA '+kind].append(target.get('UUID'))
            uuid_by_source[(kind.lower(),source['index'])]=target.get('UUID')
            audit.append({'type':kind+'_CHANNEL','source':alias,'detail':f'RX {rx} TX {tx}',
               'target':target.get('UUID'),'status':'IMPORTED; '+(f'DECODED {source["timeslot"]}; TX {source["tx_contact_name"]} / {source["tx_contact_call_id"]}' if kind=='DIGITAL' else 'ANALOG TONES FROM RCDX')})
    if any(v for lookup in indexed.values() for v in lookup.values()):
        raise ValueError('Some decoded RCDX channels were not imported')
    return assignments,uuid_by_source

def import_zones(groups,source_zones,uuid_by_source,audit):
    g=groups['Zone'];prototype=next(x for x in recs(g) if get(x,'ZP_ZONETYPE')=='NORMAL')
    item_template=recs(find_child(prototype,'ZoneItems'))[0]
    made=[];channel_zone={}
    for source in source_zones:
        if source['inconsistent_member_counts']:
            raise ValueError('Source zone member counts disagree; aborting unverified zone import: '+source['name'])
        members=source['members']
        if len(members)>16:raise ValueError('Motorola target zone capacity 16 exceeded by '+source['name'])
        zone=clone(prototype,len(recs(g)))
        name=source['name'][:16]
        setf(zone,'ZP_ZONEALIAS',name)
        setf(zone,'ZP_ZONETYPE','NORMAL')
        items=find_child(zone,'ZoneItems')
        for el in list(items):
            if is_record(el):items.remove(el)
        for mi,m in enumerate(members):
            key=(m['type'],m['source_index'])
            if key not in uuid_by_source:raise ValueError(f'Hytera zone member {source["name"]} #{mi} missing {key}')
            zitem=clone(item_template,mi)
            setf(zitem,'ZP_PERSIT',uuid_by_source[key])
            channel_zone.setdefault(uuid_by_source[key],zone.get('UUID'))
            items.append(zitem)
        g.append(zone);made.append(name)
        audit.append({'type':'DECODED_ZONE','source':source['name'],'detail':str(len(members))+' ordered members',
                      'target':zone.get('UUID'),'status':'EXACT RCDX ZONE ORDER VERIFIED'})
    # Motorola scan/roam members require a zone-qualified personality reference.
    # Preserve original Hytera zones and add explicit recovery zones for personalities
    # that were programmed but omitted from every source zone.
    orphan_ids=[uid for uid in uuid_by_source.values() if uid not in channel_zone]
    for start in range(0,len(orphan_ids),16):
        batch=orphan_ids[start:start+16]
        zone=clone(prototype,len(recs(g)))
        label=safe_alias(f'UNZONED {start//16+1}')[:16]
        setf(zone,'ZP_ZONEALIAS',label)
        setf(zone,'ZP_ZONETYPE','NORMAL')
        items=find_child(zone,'ZoneItems')
        for el in list(items):
            if is_record(el):items.remove(el)
        for pos,uid in enumerate(batch):
            item=clone(item_template,pos)
            setf(item,'ZP_PERSIT',uid)
            items.append(item)
            channel_zone[uid]=zone.get('UUID')
        g.append(zone)
        made.append(label)
        audit.append({'type':'RECOVERY_ZONE','source':'Hytera channels absent from source zones',
                      'detail':f'{label}: {len(batch)} personalities; original zones unchanged',
                      'target':zone.get('UUID'),'status':'ADDED TO ENABLE MOTOROLA ZONE-QUALIFIED SCAN REFERENCES'})
    return made,channel_zone

def import_scans_roams(groups,decoded,uuid_by_source,channel_zone,audit,warnings):
    # This tested template uses 16 scan slots maximum (including SELECTED).
    # A source list with >15 actual members must be split; don't attach a
    # half-scan to an active channel and misrepresent its scan behavior.
    created={'scan':{},'roam':{}}
    made=[]
    for kind,group,inner,namefield,ref_field,zone_field in [
        ('scan','ScanItems','ScanListItems','SP_SCANLISTALIAS','SP_CNVPERCOMP','SP_CNVPERCOMP_Zone'),
        ('roam','RoamList','RoamListItems','SSP_SCANLISTALIAS','SSP_CNVPERCOMP','SSP_CNVPERCOMP_Zone')]:
        target=groups[group]
        original=recs(target)
        if not original:raise ValueError(f'Motorola template missing {group} prototype')
        proto=original[0]
        subproto=recs(find_child(proto,inner))[0]
        for lst in decoded[kind+'_lists']:
            source_items=[m for m in lst['members'] if m['type']!='selected']
            if not lst['members'] or lst['members'][0]['type']!='selected':
                raise ValueError(f'Unexpected {kind} list sentinel in '+lst['name'])
            splits=[source_items[i:i+15] for i in range(0,len(source_items),15)] or [[]]
            if len(splits)>1:
                warnings.append(f'Hytera scan list {lst["name"]} contains {len(source_items)} actual channels; split into {len(splits)} '
                    'Motorola lists (max 16 members including Selected). No automatic scan activation assigned.')
            uuids=[]
            for part,chunk in enumerate(splits,1):
                new=clone(proto,len(recs(target)))
                alias=lst['name'] + (f' {part}' if len(splits)>1 else '')
                alias=safe_alias(alias)
                setf(new,namefield,alias)
                content=find_child(new,inner)
                for r in list(content):
                    if is_record(r):content.remove(r)
                member_ids=[]
                for i,m in enumerate(chunk):
                    key=(m['type'],m['source_index'])
                    if key not in uuid_by_source:raise ValueError(f'{kind} list unknown channel {lst["name"]}: {key}')
                    uuid=uuid_by_source[key]
                    if uuid not in channel_zone:
                        raise ValueError(f'{kind} list contains channel outside all source zones; cannot set Motorola zone-qualified reference: {m["name"]}')
                    item=clone(subproto,i)
                    setf(item,ref_field,uuid)
                    setf(item,zone_field,channel_zone[uuid])
                    content.append(item);member_ids.append(uuid)
                target.append(new);uuids.append(new.get('UUID'))
                made.append((kind,alias,new.get('UUID'),member_ids))
                audit.append({'type':kind.upper()+'_LIST','source':lst['name'],'detail':alias,
                              'target':new.get('UUID'),'status':f'{len(member_ids)} decoded, ordered members'})
            if len(uuids)==1:
                created[kind][lst['index']]=uuids[0]
            else:created[kind][lst['index']]=None
    # Attach valid one-to-one, completely recovered lists only.
    for ch in decoded['digital_channels']:
        uuid=uuid_by_source[('digital',ch['index'])]
        rr=next(r for r in recs(groups['ConventionalPersonality']) if r.get('UUID')==uuid)
        typ=ch['scan_roam_type']
        if typ=='Roam list':kind='roam'
        elif typ=='Scan list':kind='scan'
        else:continue
        ref=created[kind].get(ch['scan_roam_index'])
        if ref:
            setf(rr,'CP_SCNROAMLISTIT',ref)
            if kind=='scan' and ch['auto_start_scan']:setf(rr,'CP_UTOSCANEN','True')
        else:
            warnings.append(f'{ch["name"]}: decoded Hytera {kind} list #{ch["scan_roam_index"]} requires manual Motorola scan association (oversized or unavailable)')
    return created,made


CATEGORIES = ('QuikCallIISystems','PCRContacts','Zone','ScanItems','RoamList','ConventionalPersonality')
NS = '{http://www.w3.org/2001/XMLSchema-instance}type'
PREFIX_VALUE_RE = re.compile(r'^([A-Za-z][\w-]*):[A-Za-z_][\w.\-]*$')
DBNODE_B64 = re.compile(rb'(?P<start><DBNodeCmpBytes>)(?P<value>[A-Za-z0-9+/=\r\n]+)(?P<end></DBNodeCmpBytes>)')


def assert_bound_qnames(xml: bytes, label: str):
    tree = LET.fromstring(xml)
    unknown=[]
    for e in tree.iter():
        for attr,value in e.attrib.items():
            if attr == NS or attr.rsplit('}',1)[-1]=='Ref':
                m = PREFIX_VALUE_RE.match(value)
                if m and m.group(1) not in e.nsmap:
                    unknown.append((LET.QName(e).localname,value))
    if unknown:
        raise ValueError(f'{label}: {len(unknown)} undeclared QName prefixes: {unknown[:5]}')
    return tree


def read_db_bytes(xml: bytes):
    ms=list(DBNODE_B64.finditer(xml))
    if len(ms)!=1:raise ValueError(f'Expected exactly one DBNodeCmpBytes value, found {len(ms)}')
    return zlib.decompress(base64.b64decode(ms[0].group('value'),validate=True),-15),ms[0]


def groups_of(root):
    top=next(el for el in root if el.get(NS)=='Record')
    return {el.get('Name'):el for el in top if el.get(NS)=='RefSet'}


def records(group):
    return [el for el in group if el.get(NS)=='Record']


def same_structure(a,b):
    """Normalize prefixes, while requiring the full original data and fields."""
    if a.tag!=b.tag or dict(a.attrib)!=dict(b.attrib) or (a.text or '')!=(b.text or '') or len(a)!=len(b):
        return False
    return all(same_structure(x,y) for x,y in zip(a,b))


def locate_closing_offsets(db: bytes):
    p=xml.parsers.expat.ParserCreate()
    stack=[];offsets={}
    def start(name,attrs):
        stack.append((name,attrs))
    def end(name):
        if len(stack)==3 and stack[-1][0]=='DBNode' and stack[-1][1].get('Name') in CATEGORIES:
            found=stack[-1][1].get('Name')
            if found in offsets:raise ValueError('Repeated group '+found)
            n=p.CurrentByteIndex
            if db[n:n+9]!=b'</DBNode>':raise ValueError(f'Unexpected closing tag for {found} at {n}')
            offsets[found]=n
        stack.pop()
    p.StartElementHandler=start;p.EndElementHandler=end;p.Parse(db,True)
    return offsets


def make_fixed(template:bytes, converted:bytes):
    source_prefix,source_hdr,source_inner,_,source_xml=dec_archive(template)
    _,_,_,_,bad_xml=dec_archive(converted)
    source_tree=assert_bound_qnames(source_xml,'Original Motorola XML')
    bad_tree=LET.fromstring(bad_xml)
    original_db,original_match=read_db_bytes(source_xml)
    failed_db,_=read_db_bytes(bad_xml)
    original_root=LET.fromstring(original_db)
    failed_root=LET.fromstring(failed_db)
    old=groups_of(original_root);new=groups_of(failed_root)
    added={}
    for category in CATEGORIES:
        if category not in old or category not in new:raise ValueError('Missing '+category)
        old_recs=records(old[category]);new_recs=records(new[category])
        if len(new_recs)<len(old_recs):raise ValueError('Original records deleted: '+category)
        for index,(x,y) in enumerate(zip(old_recs,new_recs)):
            if not same_structure(x,y):raise ValueError(f'Original Motorola record was changed: {category} #{index}')
        made=new_recs[len(old_recs):]
        added[category]=made
    offsets=locate_closing_offsets(original_db)
    if set(offsets)!=set(CATEGORIES):raise ValueError('Could not identify all Motorola RefSet ending positions')
    patched_db=original_db
    for category,at in sorted(offsets.items(),key=lambda kv:kv[1],reverse=True):
        # Each appended record is serialized with all namespace bindings it needs.
        appended=b''.join(LET.tostring(el,encoding='utf-8') for el in added[category])
        patched_db=patched_db[:at]+appended+patched_db[at:]
    out_root=LET.fromstring(patched_db)
    result=groups_of(out_root)
    for category in CATEGORIES:
        if len(records(result[category]))!=len(records(new[category])):
            raise ValueError('Post-patch record count mismatch: '+category)
        for index,(x,y) in enumerate(zip(records(result[category]), records(new[category]))):
            if not same_structure(x,y):raise ValueError(f'Post-patch record mismatch: {category} #{index}')
    comp=zlib.compressobj(9,zlib.DEFLATED,-15)
    coded=base64.b64encode(comp.compress(patched_db)+comp.flush())
    fixed_xml=source_xml[:original_match.start('value')]+coded+source_xml[original_match.end('value'):]
    assert_bound_qnames(fixed_xml,'Repaired Motorola XML')
    verified_db,_=read_db_bytes(fixed_xml)
    if verified_db!=patched_db:raise ValueError('Compressed DBNode round-trip mismatch')
    # This used to fail: 98 xsi:type QName values lost their namespace binding.
    output=pack_archive(source_prefix,source_hdr,source_inner,fixed_xml)
    _,_,_,_,unwrapped=dec_archive(output)
    if unwrapped!=fixed_xml:raise ValueError('Encrypted archive did not round-trip byte-perfectly')
    if len(records(groups_of(LET.fromstring(verified_db))['ConventionalPersonality'])) != len(records(new['ConventionalPersonality'])):
        raise ValueError('Converted personality count was not preserved')
    return output,{
        'result':'XML namespace bug fixed and verified; MOTOROLA CPS NOT YET TESTED',
        'original_xctb_sha256':hashlib.sha256(template).hexdigest(),
        'prior_invalid_xctb_sha256':hashlib.sha256(converted).hexdigest(),
        'output_xctb_sha256':hashlib.sha256(output).hexdigest(),
        'original_outer_xml_bytes_preserved_except_DBNodeCmpBytes':True,
        'original_inner_DBNode_bytes_preserved_except_appended_new_records':True,
        'undeclared_i_type_prefixes_in_prior_output':sum(
            1 for e in bad_tree.iter() for a,v in e.attrib.items()
            if a==NS and PREFIX_VALUE_RE.match(v) and PREFIX_VALUE_RE.match(v).group(1) not in e.nsmap),
        'undeclared_i_type_prefixes_in_repaired_output':0,
        'records_appended':{k:len(v) for k,v in added.items()},
        'original_dbnode_length':len(original_db),'repaired_dbnode_length':len(patched_db),
        'important':'CPS must accept the file and validate content before any radio is programmed.'}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('rcdx',type=Path,help='Hytera RCDX source, decoded and semantically parsed')
    ap.add_argument('template',type=Path,help='User-owned MOTOROLA CPS2 .xctb template')
    ap.add_argument('-o','--output',required=True,type=Path)
    a=ap.parse_args()
    inputs={p.resolve() for p in (a.rcdx,a.template)}
    output=a.output.resolve()
    if output in inputs or output.exists():raise ValueError('Refusing to overwrite any input or existing output')
    if output.suffix.lower()!='.xctb':raise ValueError('Output must have .xctb extension')
    raw_source=a.rcdx.read_bytes();hdr=verify_rcdx(raw_source)
    decoded=parse_plaintext(decrypt_rcdx(raw_source))
    if any(decoded['statistics'].get('unresolved_'+kind+'_members',0) for kind in ('zone','scan','roam')):
        raise ValueError('Source RCDX has unresolved zone channel references; see extractor warnings. Conversion stopped to avoid silently dropping channels.')
    if decoded['statistics']['inconsistent_zone_count_records']:
        raise ValueError('RCDX source has inconsistent zone count records; refusing conversion')
    # Audit every source tone before modifying the Motorola template. Never
    # guess a Quick Call II code or silently substitute a PL/DPL tone.
    unsupported=[]
    for c in decoded['analog_channels']:
        for side in ('rx','tx'):
            kind=c[side+'_tone_type']; value=c[side+'_tone_value']
            if kind=='CTCSS' and tone_key(value) not in TPL_CODE:
                unsupported.append(f"{c['name']} {side.upper()} CTCSS {value} Hz: no verified Motorola PL code")
            elif kind=='CDCSS Inverted':
                unsupported.append(f"{c['name']} {side.upper()} inverted DCS {value}: polarity support not verified")
            elif kind not in ('None','CTCSS','CDCSS','CDCSS Inverted'):
                unsupported.append(f"{c['name']} {side.upper()} unknown tone type {kind!r}")
    # Unsupported QCII contacts are omitted from Motorola, but retained in
    # the separate import-error report. Never fabricate CAP/Quick Call codes.
    qc_skipped=[]
    qc_accepted=[]
    for c in decoded['two_tone_contacts']:
        fmt=c['encode_format'].strip().lower()
        first=tone_key(c['first_tone_hz'])
        second=tone_key(c['second_tone_hz'])
        reason=None
        if fmt not in ('two tone','long tone'):
            reason='unsupported Quick Call II format '+repr(c['encode_format'])
        elif first not in TONE_CODE or (fmt=='two tone' and second not in TONE_CODE):
            reason=f'no verified Motorola Quick Call II CAP code for {first}/{second} Hz'
        elif fmt=='long tone':
            # A long-tone entry can only be imported if its Motorola system
            # already exists; validate before entering register_contacts.
            reason='long-tone system must be matched against Motorola template'
        if reason:
            qc_skipped.append({'name':c['name'],'format':c['encode_format'],
                'first_hz':c['first_tone_hz'],'second_hz':c['second_tone_hz'],
                'reason':reason})
        else:
            qc_accepted.append(c)
    if unsupported:
        report=a.output.with_suffix('.unsupported-tones.txt')
        if report.exists():raise ValueError('Refusing to overwrite existing tone report '+str(report))
        report.write_text('UNSUPPORTED SOURCE TONES - CONVERSION NOT PERFORMED\n'+'\n'.join(unsupported)+'\n',encoding='utf-8')
        raise ValueError(f'{len(unsupported)} unsupported tone assignment(s); complete list: {report}')
    # Single-step conversion: construct the existing internal import-row shape
    # directly from the decoded RCDX records, never from Excel worksheets.
    dig=[];ana=[]
    for kind,source,dest in (('digital',decoded['digital_channels'],dig),('analog',decoded['analog_channels'],ana)):
        for c in source:
            row={'Channel Alias':c['name'],
                 'Receive Frequency [MHz]':freq(c['rx_mhz']),
                 'Transmit Frequency [MHz]':freq(c['tx_mhz']),
                 'Power Level':c['power_level'],
                 'Rx Only':'Enable' if c['rx_only'] else 'Disable',
                 'Tx Time-out Time [s]':str(c['tx_timeout_s']),
                 'TOT Re-key Time [s]':'0',
                 'Talk Around':'Disable'}
            if kind=='digital':
                row['Color Code']=str(c['color_code'])
            else:
                # RCDX parser currently does not identify analog spacing or
                # TOT re-key. Use explicit provisional values and audit them.
                row['Channel Spacing [KHz]']='12.5'
                for side,short in (('Rx','rx'),('Tx','tx')):
                    t=c[short+'_tone_type'];v=c[short+'_tone_value']
                    if t=='CDCSS Inverted':
                        raise ValueError('Inverted DCS not yet supported for '+c['name'])
                    row[side+' CTCSS/CDCSS Type']='Off' if t=='None' else t
                    row['CTCSS' if side=='Rx' else 'CTCSS__2']=str(v if t=='CTCSS' else '0')
                    row['CDCSS' if side=='Rx' else 'CDCSS__2']=str(v if t=='CDCSS' else '000')
            dest.append(row)
    contacts=[{'Call Alias':c['name'],'Call Type':c['call_type'],'Call ID':str(c['call_id'])}
              for c in decoded['dmr_contacts']]
    tones=[{'Call Alias':c['name'],'Encode Format':c['encode_format'],
            '1st Tone Frequency [Hz]':str(c['first_tone_hz']),
            '2nd Tone Frequency [Hz]':str(c['second_tone_hz'])}
           for c in qc_accepted]
    template=a.template.read_bytes();prefix,head,inner,radio,xml=dec_archive(template)
    work=next(x for x in radio if x.tag.rsplit('}',1)[-1]=='WorkingCodeplug')
    configuration=next(x for x in work if x.tag.rsplit('}',1)[-1]=='Configuration')
    dbfield=next(x for x in configuration if x.tag.rsplit('}',1)[-1]=='DBNodeCmpBytes')
    original=base64.b64decode(''.join(dbfield.text.split()),validate=True)
    db_bytes=zlib.decompress(original,-15)
    db=ET.fromstring(db_bytes)
    top=next(x for x in db if is_record(x))
    groups={x.get('Name'):x for x in top if x.get(XS)=='RefSet'}
    required=('ConventionalPersonality','PCRContacts','QuikCallIISystems','Zone')
    for name in required:
        if name not in groups:raise ValueError('Motorola template lacks required collection '+name)
    orig_stats={k:len(recs(groups[k])) for k in required}
    extra_orig={k:len(recs(groups[k])) for k in ('ScanItems','RoamList')}
    original_records={k: [ET.tostring(r,encoding='utf8') for r in recs(groups[k])] for k in required}
    audit=[];warnings=[]
    from hytera_extract import capitalization_collisions
    existing_zone_names=[get(z,'ZP_ZONEALIAS') for z in recs(groups['Zone'])]
    source_zone_names=[z['name'][:16] for z in decoded['zones']]
    capitalization_warnings=capitalization_collisions(existing_zone_names+source_zone_names)
    for variants in capitalization_warnings:
        warnings.append('CASE-ONLY ZONE NAME COLLISION (preserved unchanged): '+repr(variants))

    contact_conflicts=0
    warnings.append('Analog channel spacing defaults to 12.5 kHz; not yet decoded from RCDX. VERIFY IN CPS.')
    warnings.append('TOT re-key delay defaults to 0 seconds; not yet decoded from RCDX. VERIFY IN CPS.')
    warnings.append('Talk-around defaults to disabled; not yet decoded from RCDX. VERIFY IN CPS.')
    contacts_from_rcdx=[{'Call Alias':c['name'],'Call Type':c['call_type'],
                         'Call ID':str(c['call_id'])} for c in decoded['dmr_contacts']]
    cstats=register_contacts(groups,contacts_from_rcdx,tones,audit,warnings)
    txcontacts=existing_contact_by_call(groups)
    assignments,uuid_by_source=import_personalities(groups,dig,ana,audit,warnings,decoded,txcontacts)
    zones,channel_zone=import_zones(groups,decoded['zones'],uuid_by_source,audit)
    mapped_lists,created_lists=import_scans_roams(groups,decoded,uuid_by_source,channel_zone,audit,warnings)
    new_stats={k:len(recs(groups[k])) for k in required}
    extra_new={k:len(recs(groups[k])) for k in ('ScanItems','RoamList')}
    # Preserve exact same original records and all untouched feature groups.
    for name in required:
        got=[ET.tostring(r,encoding='utf8') for r in recs(groups[name])[:orig_stats[name]]]
        if got!=original_records[name]:raise ValueError('Original Motorola records changed in '+name)
    for name,val in (('ConventionalPersonality',len(dig)+len(ana)),
                     ('PCRContacts',cstats['digital_contacts_created']+len(tones)),
                     ('QuikCallIISystems',cstats['two_tone_systems_created']),
                     ('Zone',len(zones))):
        if new_stats[name]-orig_stats[name]!=val:raise ValueError('Record count mismatch '+name)
    uncmp=zlib.compressobj(9,zlib.DEFLATED,-15)
    dbfield.text=base64.b64encode(uncmp.compress(ET.tostring(db,encoding='utf-8'))+uncmp.flush()).decode()
    output_bytes=pack_archive(prefix,head,inner,radio)
    # CRITICAL CPS compatibility fix: ElementTree removes namespace bindings
    # that are referenced only by QName-valued xsi:type XML attributes.
    # Rebuild from the untouched native Motorola outer/inner XML, transplanting
    # ONLY records appended by this converter. This avoids undeclared d: types.
    output_bytes,preservation_report=make_fixed(template,output_bytes)
    # Independently decrypt new archive, validate SHA256 and reexpand all DBNodes.
    _,_,_,check_radio,_=dec_archive(output_bytes)
    w=next(x for x in check_radio if x.tag.rsplit('}',1)[-1]=='WorkingCodeplug')
    cfg=next(x for x in w if x.tag.rsplit('}',1)[-1]=='Configuration')
    ef=next(x for x in cfg if x.tag.rsplit('}',1)[-1]=='DBNodeCmpBytes')
    checked=zlib.decompress(base64.b64decode(ef.text),-15)
    validate=ET.fromstring(checked)
    check_top=next(x for x in validate if is_record(x));check_groups={x.get('Name'):x for x in check_top if x.get(XS)=='RefSet'}
    if {k:len(recs(check_groups[k])) for k in required}!=new_stats:raise ValueError('Repacked archive lost records')
    # Verify additional scan/roam list records were preserved.
    for k in extra_new:
        if len(recs(check_groups[k]))!=extra_new[k]:raise ValueError('List count mismatch '+k)
    for kind,alias,lid,members in created_lists:
        gr=check_groups['ScanItems' if kind=='scan' else 'RoamList']
        sub='ScanListItems' if kind=='scan' else 'RoamListItems'
        ref='SP_CNVPERCOMP' if kind=='scan' else 'SSP_CNVPERCOMP'
        r=next(x for x in recs(gr) if x.get('UUID')==lid)
        actual=[get(x,ref) for x in recs(find_child(r,sub))]
        if actual!=members:raise ValueError('Scan/roam member verification failed '+alias)
    # Verify every imported channel's exact RX/TX field and zone membership.
    allchannels={r.get('UUID'):r for r in recs(check_groups['ConventionalPersonality'])}
    for modality,source_items in [('DIGITAL',dig),('ANALOG',ana)]:
        ids=assignments['HYTERA '+modality]
        if len(ids)!=len(source_items):raise ValueError('Channel count mismatch')
        for c,id in zip(source_items,ids):
            rr=allchannels[id]
            if (get(rr,'CP_RXFREQ'),get(rr,'CP_TXFREQ'))!=(freq(c['Receive Frequency [MHz]']),freq(c['Transmit Frequency [MHz]'])):
                raise ValueError('Channel frequency mismatch '+c['Channel Alias'])
    # Assert decoded timeslots and TX contact UUIDs survived archive repacking.
    for source in decoded['digital_channels']:
        rr=allchannels[uuid_by_source[('digital',source['index'])]]
        if get(rr,'CP_SLTASSGMNT')!=('SLOT1' if source['timeslot']=='Slot 1' else 'SLOT2'):
            raise ValueError('Timeslot not preserved: '+source['name'])
        typ={'Group Call':'GRPCALL','Private Call':'PRIVCALL','All Call':'ALLCALL'}
        key=(str(source['tx_contact_call_id']),typ[source['tx_contact_call_type']])
        if get(rr,'CP_UKPPERS')!=txcontacts[key]:
            raise ValueError('TX contact reference not preserved: '+source['name'])
        decoded_list_type=source['scan_roam_type']
        mapped_kind={'Scan list':'scan','Roam list':'roam'}.get(decoded_list_type)
        expected_list=(mapped_lists[mapped_kind].get(source['scan_roam_index'])
                       if mapped_kind else None)
        actual_list=get(rr,'CP_SCNROAMLISTIT')
        if actual_list!=(expected_list or 'NONE'):
            raise ValueError('Scan/roam association mismatch: '+source['name'])
    target_new_zones=recs(check_groups['Zone'])[orig_stats['Zone']:]
    if len(target_new_zones)!=len(zones):raise ValueError('Imported and recovery zone count mismatch')
    for src,zo in zip(decoded['zones'],target_new_zones):
        real=[get(m,'ZP_PERSIT') for m in recs(find_child(zo,'ZoneItems'))]
        expected=[uuid_by_source[(m['type'],m['source_index'])] for m in src['members']]
        if real!=expected:raise ValueError('Zone ordering mismatch: '+src['name'])
    zone_ids=set()
    for item in recs(check_groups['Zone']):
        for z in recs(find_child(item,'ZoneItems')):
            cid=get(z,'ZP_PERSIT')
            if cid in set(sum(assignments.values(),[])):zone_ids.add(cid)
    zone_expected={uuid_by_source[(m['type'],m['source_index'])] for z in decoded['zones'] for m in z['members']}
    imported_ids=set(sum(assignments.values(),[]))
    if zone_ids!=imported_ids:raise ValueError('Some imported channels are missing from original or recovery zones')
    recovery=target_new_zones[len(decoded['zones']):]
    recovered={get(m,'ZP_PERSIT') for z in recovery for m in recs(find_child(z,'ZoneItems'))}
    if recovered!=(imported_ids-zone_expected):raise ValueError('Recovery zone membership mismatch')
    if recovered:warnings.append(f'{len(recovered)} channels absent from source zones placed in added UNZONED recovery zones; source zone order unchanged')
    report={
      'result':'STRUCTURALLY VERIFIED; NOT CPS GUI OR RADIO VERIFIED',
      'source_file':a.rcdx.name,'source_rcdx_sha256':sha(raw_source),'source_header':hdr,
      'source_excel_export_sha256':{},
      'source_alias_frequency_and_tone_sheet_values_verified':False,
      'source_spreadsheet_contact_call_types_disagree_with_rcdx':bool(contact_conflicts),
      'source_rcdx_decoded':True,
      'decoded_rcdx_statistics':decoded['statistics'],
      'template_xctb_name':a.template.name,'template_xctb_sha256':sha(template),
      'output_xctb_name':output.name,'output_sha256':sha(output_bytes),
      'original_record_counts':{**orig_stats,**extra_orig},'result_record_counts':{**new_stats,**extra_new},
      'source_scan_roam_lists_decoded':True,
      'created_motorola_lists':[(kind,name,len(ids)) for kind,name,_,ids in created_lists],
      'original_radio_records_unchanged':True,
      'original_outer_xml_and_dbnode_bytes_preserved':True,
      'repaired_undeclared_xsi_type_prefixes':preservation_report['undeclared_i_type_prefixes_in_prior_output'],
      'capitalization_collisions':{'combined_zones':capitalization_warnings, **decoded['capitalization_collisions']},
      'new_digital_channels':len(dig),
      'new_analog_channels':len(ana),'source_dmr_contacts':len(contacts),
      'source_two_tone_contacts':len(decoded['two_tone_contacts']),
      'imported_two_tone_contacts':len(tones),'skipped_two_tone_contacts':qc_skipped,'new_zone_names':zones,
      **cstats,
      'source_password_fields':decoded['password_fields'],
      'legacy_worksheet_columns_not_mapped_to_motorola':{
        'Digital Channel':['Tx Admit','TOT Pre-Alert Time [s]','TOT Reset Time [s]','RSSI Threshold'],
        'Analog Channel':['Rx Squelch Mode','Monitor Squelch Mode','Channel Change Squelch Mode',
          'Carrier Squelch Level','Tx Admit','TOT Pre-Alert Time [s]','TOT Reset Time [s]',
          'Auto Reset Mode','Auto Reset Time [s]','Call Answer Time [s]',
          'CTCSS Tail Revert Option [Radians]','CTCSS Tail Revert','RSSI Threshold']},
      'MISSING_OR_UNVERIFIED':['Analog channel spacing defaults to 12.5 kHz; verify before programming', 'TOT re-key delay and talk-around defaults require verification', 'Hytera RX group list has no active entries and was not mapped',
       'Scan lists exceeding the target 16-member limit are split; split copies are not auto-assigned',
       'Hytera general settings/keys/radio alias not imported',
       'Hytera Always Allow transmit-admit setting not independently mapped to Motorola',
       'Motorola TPL mappings sourced from supplied motorolacodes.xlsx Legacy PL column; validate in CPS',
       'CPS desktop and radio programming acceptance not tested'],
      'EXCLUDED_BY_REQUEST':['HDC1200','5-Tone','Phone List'],
      'warnings':warnings + [f"Skipped Quick Call II contact {c['name']}: {c['reason']}" for c in qc_skipped]}
    # Preflight all output files before any publication.
    report_file=output.with_suffix('.audit.json');csvfile=output.with_suffix('.audit.csv')
    errorfile=output.with_suffix('.import-errors.txt')
    for p in (output,report_file,csvfile,errorfile):
        if p.resolve() in inputs or p.exists():raise FileExistsError('Output exists or conflicts with source: '+str(p))
    output.parent.mkdir(parents=True,exist_ok=True)
    error_lines=['HYTERA TO MOTOROLA IMPORT ERRORS',
        'Unsupported Quick Call II contacts were NOT imported; source RCDX is unchanged.',
        'Do not program the radio without reviewing omitted entries.', '']
    for item in qc_skipped:
        error_lines.append(f"SKIPPED QCII CONTACT: {item['name']} | {item['format']} | {item['first_hz']}/{item['second_hz']} Hz | {item['reason']}")
    if not qc_skipped:error_lines.append('No skipped Quick Call II contacts.')
    errorfile.write_text('\n'.join(error_lines)+'\n',encoding='utf-8')
    with output.open('xb') as f:f.write(output_bytes)
    report_file.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf8')
    with csvfile.open('x',newline='',encoding='utf-8-sig') as f:
        writer=csv.DictWriter(f,fieldnames=['type','source','detail','target','status']);writer.writeheader();writer.writerows(audit)
    print(json.dumps({'output':str(output),'decoded_and_repacked_sha256_verified':True,'hytera_timeslots_txcontacts_zones_mapped':True,
         'original_Motorola_records_preserved':True,'digital':len(dig),'analog':len(ana),
         'two_tone_imported':len(tones),'two_tone_skipped':len(qc_skipped),'import_errors':str(errorfile),'new_zones':len(zones),'new_total_personalities':new_stats['ConventionalPersonality'],
         'audit':str(report_file),'warnings':len(warnings)},indent=2))

if __name__=='__main__':
    try:main()
    except (OSError,ValueError,KeyError,IndexError,ET.ParseError,TypeError) as e:sys.exit('ERROR: '+str(e))

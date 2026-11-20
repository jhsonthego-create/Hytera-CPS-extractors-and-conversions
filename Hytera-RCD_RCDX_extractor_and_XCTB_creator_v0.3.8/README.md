# Hytera RCDX to Motorola XCTB — v0.3.7

One command, no CSV or Excel dependencies:

```bash
python3 hytera_to_xctb.py SOURCE.rcdx ORIGINAL-MOTOROLA-TEMPLATE.xctb -o NEW.xctb
```

Requires Python 3.9+, `cryptography` and `lxml`. The template must be compatible Motorola CPS2 data model 2.153.50. Do not use an already-converted XCTB as a template.

**Quick Call II behavior:** Unknown CAP/Quick Call II codes are never guessed. Unsupported two-tone contacts are skipped, and the converter continues with supported data. `NEW.import-errors.txt` lists every omitted contact, original frequency pair, and reason. `NEW.audit.json` also records skipped entries. A blank-error report is generated when none are skipped. No invalid partial Motorola Quick Call II records are written.

Other structural errors (missing channel references, unknown CTCSS mappings, unsupported DCS polarity, invalid Motorola template) remain fatal rather than silently corrupting channels. Conversion is not proof of Motorola CPS acceptance or safe radio programming. Review all omissions and provisional analog settings in CPS before programming. Source RCDX and template are never modified.

Optional CSV/JSON source export:

```bash
python3 hytera_extract.py SOURCE.rcdx --outdir csv
```

Source exports can contain private password fields; do not publish them.

## v0.3.8: Channels outside all Hytera zones

The converter preserves all original Hytera zone memberships and creates
additional `UNZONED 1`, `UNZONED 2`, etc. recovery zones (16 channels maximum
per zone) for imported channels absent from every source zone. This enables
Motorola scan and roaming lists to reference those personalities without
aborting conversion. The audit marks every recovery zone; review its members
in Motorola CPS before programming. Existing Motorola template records are
left untouched. Unresolved references to channels not present in the RCDX
remain fatal rather than being silently invented.

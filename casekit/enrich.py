"""Event enrichment applied before detection.

Currently: decode PowerShell ``-EncodedCommand`` payloads. Attackers encode
commands to hide them from a casual read of the logs; the encoding is plain
Base64 over UTF-16LE, so the analyst can - and should - read what actually
ran. The decoded text is stored as ``DecodedCommand`` so rules, IOC
extraction and the report all see it.
"""
from __future__ import annotations

import base64
import binascii
import re
from typing import List, Optional

from casekit.models import Event

ENC_FLAG = re.compile(r"\s-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand|ec)\s+([A-Za-z0-9+/=]{16,})",
                      re.IGNORECASE)


def decode_powershell(cmdline: str) -> Optional[str]:
    m = ENC_FLAG.search(" " + cmdline)
    if not m:
        return None
    blob = m.group(1)
    blob += "=" * (-len(blob) % 4)
    try:
        return base64.b64decode(blob).decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError):
        return None


def enrich(events: List[Event]) -> List[Event]:
    for e in events:
        cmd = e.fields.get("CommandLine") or e.fields.get("ImagePath")
        if cmd and "powershell" in str(cmd).lower():
            decoded = decode_powershell(str(cmd))
            if decoded:
                e.fields["DecodedCommand"] = decoded
    return events

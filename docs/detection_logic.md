
# OS derection logic detail

Before all, we should give up comprehensive OS detection result. Migrate to each's method's result only. Give final decision chance to users.

## DHCP OS detection

fingerprniting:
- DHCP paramter request list (option 55)
- DHCP vendor class identifier (option 60)
- DHCP host name (option 12) OR DHCP user class (option 77)

analyze algorithm:
fingerback table matching

@https://github.com/karottc/fingerbank/blob/master/dhcp_fingerprints.conf

## mDNS OS detection

Here is fingerprint - OS corresponding table.

| Observation                                                                 | Fingerprint                          | Deduced OS (and version)                             |
|------------------------------------------------------------------------------|--------------------------------------|-------------------------------------------------------|
| **DNS-SD service** `<device-info>._tcp.local`<br/>TXT keys include `osxvers` | `model`, `osxvers`                   | **macOS**<br/>Version = `osxvers − 4` (e.g. 20 → 16 → 11.0)  |
| **same** `<device-info>._tcp.local`<br/>TXT keys include `deviceid`,`osv`     | `model`=`iPhone*`/`iPad*`, `osv`     | **iOS / iPadOS**<br/>Version = `osv`                   |
| **same** `<device-info>._tcp.local`<br/>TXT keys include `firmwarever`       | `model`=`AppleTV*` or HomeKit types  | **tvOS / HomeKit**<br/>Firmware = `firmwarever`        |
| **DNS-SD service** `<workstation>._tcp.local`<br/>TXT: only `org.freedesktop.Avahi.cookie` | none of the Apple keys above         | **Linux** (Avahi)                                      |
| **only** service `_smb._tcp.local` (and no `<device-info>`)                  | no DNS-SD TXT records other than SMB | **Windows** (possibly Bonjour installed)               |
| **mix of** `_ipp._tcp.local`, TXT keys `txtvers`, `URF=`, `TBCP=`             | IPP printer stack                    | **Printer appliance / embedded OS**                    |
| **any** service with entirely missing TXT record or malformed TXT            | non-standard mDNS stack (lwIP, etc.) | **IoT / embedded**—fingerprint by violation pattern   |

### fingerprint must capture
- <device-info>._tcp.local
- _smb._tcp.local (and no <device-info>)
- _ipp._tcp.local

### sample logic for analyze

```python
# assume get_services() → list of service-types advertised
#       get_txt(svc)      → dict of TXT key→value for that service

services = get_services()
txt = { svc: get_txt(svc) for svc in services }

if "_device-info._tcp.local" in services:
    info = txt["_device-info._tcp.local"]
    if "osxvers" in info:
        ver = int(info["osxvers"]) - 4
        os = f"macOS {ver}"
    elif "deviceid" in info and "osv" in info:
        os = f"iOS {info['osv']}"
    elif "firmwarever" in info:
        os = f"tvOS/HomeKit (fw {info['firmwarever']})"
    else:
        os = f"Apple device (model {info.get('model','?')})"

elif "_workstation._tcp.local" in services \
     and "org.freedesktop.Avahi.cookie" in txt["_workstation._tcp.local"]:
    os = "Linux (Avahi)"

elif "_smb._tcp.local" in services \
     and "_device-info._tcp.local" not in services:
    os = "Windows"

elif any(svc.startswith("_ipp._tcp.local") for svc in services):
    os = "Printer/embedded (IPP stack)"

else:
    os = "Unknown/IoT (non-standard mDNS stack)"

```

## SSDP OS detection

SSDP suggestion from specialist

| Header                    | Windows                                                   | macOS / iOS                             | Linux (mini-upnpd, GUPnPd…)            |
   |---------------------------|-----------------------------------------------------------|-----------------------------------------|----------------------------------------|
   | `SERVER`                  | `Windows/10.0 UPnP/1.0 Windows-ConnectNow/1.0`            | `Darwin/18.2.0 UPnP/1.1`                | `Linux/4.15.0-54-generic UPnP/1.0 …`   |
   | `BOOTID.UPNP.ORG`         | present (Vista+)                                          | present                                 | often absent or vendor-spe ([API documentation - Fingerbank](https://api.fingerbank.org/api_doc/2/combinations/interrogate.html?utm_source=chatgpt.com)) `MX`                      | `MX: 2`                                                   | usually `MX: 3`                         | `MX: 3` or higher, varies by SDK       |
   | `Cache-Control: max-age`  | `max-age=1800`                                            | `max-age=1800`                          | often shorter (e.g. `max-age=120`)     |
   | Header order & casing     | ALL-CAPS, ordered as in Microsoft’s reference code        | mix ([セキュリティチェックに「Censys」を使ったら便利だった件について](https://qiita.com/fujihide/items/b1a9fe342a482dacc655?utm_source=chatgpt.com))ple’s implementation | lowercase or mixed, code-order driven  |
   | `LOCATION` path & port    | `/rootDesc.xml` on 1900/5000                              | `/DeviceDescription.xml` on 49152       | `/desc.xml` on ephemeral port          |

### fingerprint must capture
header in the table

### analyze
heuristic ruls in the table

## TCP Syn detection

According to p0f signature method

`olen:ttl:tos:mss:win:opts:quirks:pclass`

### fingerprnit must capture
- TCP options list keeps order
- MSS
- Window size
- TTL
- TOS

### Analysis method
matching TCP signature part of fp file in p0f

## OUI and vendor purpose analysis

Currently, OUI-producy category mapping method is researched.
In this project, implement followings as preparation:

- When vendor analysis is needed, look up nmap information file and got vendor name
- If vendor name is got, look up manual created vendor - category map and report it as OUI analysis result
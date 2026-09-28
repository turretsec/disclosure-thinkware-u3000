# Thinkware U3000 Dashcam: Security Vulnerabilities
 
Three vulnerabilities in the Thinkware U3000 dashcam's local WiFi control protocol, discovered through reverse engineering the official Android app and confirmed against real hardware. All three require only local network access: no physical access to the device, no prior authentication, and no cooperation from the device owner.
 
> Disclosed to Thinkware on 2026-06-21. The 30-day disclosure window has closed with only a non-technical acknowledgment of receipt.
 
## Why this matters
 
Dash cams are an unusual category for this kind of exposure. They continuously record a vehicle's movements, and they frequently change hands through rentals, fleet management, and used car sales. Whoever currently has access to the vehicle doesn't necessarily control the network it's configured on. Combined with an arbitrary file write primitive and zero authentication on the control protocol, this goes beyond a privacy concern. It's also a tampering concern: any file on the device, not just video, can be altered or replaced without the owner's knowledge.
 
This also isn't the first time a vulnerability of this shape has shown up in a Thinkware dash cam. Independent researcher **geo-chen** previously disclosed several issues in the related F800 Pro model; see [geo-chen/Thinkware-Dashcam](https://github.com/geo-chen/Thinkware-Dashcam). Those generally required physical or local filesystem access to exploit. The findings below require neither: network access alone is enough, and the file-write finding is a stronger capability than anything in that prior set.
 
> **Note on affected model:** all findings below were confirmed against the base Thinkware **U3000**. Thinkware also sells a separate "U3000 Pro" variant; whether it shares the same protocol implementation has not been tested.
 
---
 
## Finding 1: Unauthenticated Arbitrary File Write
> **CVE:** CVE-2026-101053 ([VulDB #410915](https://vuldb.com/vuln/410915))

> **Full writeup:** [`findings/01-arbitrary-file-write.md`](findings/01-arbitrary-file-write.md)
 
**Product:** Thinkware U3000 Dashcam

**Affected component:** TCP control protocol (port 7878 command / port 8787 data), no authentication

**Attack vector:** Any device on the same local network can write attacker-controlled content to any absolute path on the device's filesystem.
 
### Description
 
The device's control protocol exposes a `PUT_FILE` command that writes attacker-supplied bytes to an attacker-supplied absolute path, with no path validation or sandboxing whatsoever. Confirmed by writing a file directly into the device's `/tmp` directory, the same directory that holds its own WiFi configuration (`wpa_supplicant.conf`) and at least one shell script (`hidraw0.sh`), and reading it back byte-for-byte to confirm exact placement.

![Put file proof](./findings/u3000_put_file_proof.png)
 
### Steps to Reproduce
 
1. Complete the session handshake: `START_SESSION` -> `SET_CLNT_INFO` -> `APP_CONNECT`.
2. Send `PUT_FILE` with `param` set to a path outside anywhere the official app would legitimately write.
3. Write the file bytes to the data socket.
4. The camera responds `{"rval": 0, "msg_id": 1286}` immediately, then later pushes an asynchronous `NOTIFICATION` (`msg_id` 7) confirming completion.
5. `LS` on the parent directory confirms the file is present under the exact requested name, alongside system files.
6. `GET_FILE` on the same path reads the content back for a byte-for-byte comparison against what was sent.
 
## Finding 2: Unauthenticated Arbitrary File Read
> **CVE:** CVE-2026-101054 ([VulDB #410916](https://vuldb.com/vuln/410916))

> **Full writeup:** [`findings/02-arbitrary-file-read.md`](findings/02-arbitrary-file-read.md)

**Product:** Thinkware U3000 Dashcam

**Affected component:** TCP control protocol (port 7878 command / port 8787 data), no authentication

**Attack vector:** Any device on the same local network can list and read any absolute path on the device's filesystem, not just recorded video.
 
### Description
 
The same protocol's `LS` and `GET_FILE` commands enumerate and read any absolute path with no restriction. Confirmed by directly reading the device's live `wpa_supplicant.conf`, which contains its real WiFi SSID and plaintext password. This is the read-side mirror of Finding 1: same root cause, opposite direction, and a mechanically distinct route to the same credentials exposed in Finding 3.

### Steps to Reproduce
 
1. Complete the session handshake: `START_SESSION` -> `SET_CLNT_INFO` -> `APP_CONNECT`.
2. `LS` on `/tmp` confirms `wpa_supplicant.conf` is present, alongside other system files (`hidraw0.sh`, `aws.dat`, `resolv.conf`, etc).
3. `GET_FILE` with `param: "/tmp/wpa_supplicant.conf"` returns the file's size, then the full content streams over the data socket exactly as it would for a video file.
4. The returned content contains `ssid=`/`psk=` lines matching the camera's actual configured network.
 
## Finding 3: Plaintext WiFi Credential Disclosure via Status Query
> **CVE:** CVE-2026-101055 ([VulDB #410917](https://vuldb.com/vuln/410917))

> **Full writeup:** [`findings/03-wifi-credential-disclosure.md`](findings/03-wifi-credential-disclosure.md)

**Product:** Thinkware U3000 Dashcam

**Affected component:** TCP control protocol (port 7878), no authentication

**Attack vector:** Any device on the same local network can retrieve the camera's WiFi password directly, with no authentication and no prior access required.
 
### Description
 
A dedicated status query, `GET_STATUS "wifi_info"`, returns the device's WiFi SSID and plaintext password directly. This is a different mechanism than Finding 2, requiring no filesystem access at all, just a normal protocol status read.
 
### Steps to Reproduce
 
1. Complete the session handshake: `START_SESSION` -> `SET_CLNT_INFO` -> `APP_CONNECT`.
2. Send `GET_STATUS` with `param: "wifi_info"`.
3. Response: `{"rval": 0, "msg_id": 2050, "type": "wifi_info", "param": [{"ssid": "<real SSID>"}, {"password": "<real plaintext password>"}, {"mac": "<real MAC>"}]}`.

 
## Disclosure Timeline
 
| Date | Event |
|---|---|
| 2026-06-19 | Findings confirmed against firmware v1.02.00 |
| 2026-06-21 | Firmware upgraded to v1.02.04 (current production release); all three findings re-confirmed, no change in behavior |
| 2026-06-21 | Vendor notified via email to support@thinkware.com |
| 2026-06-22 (approx.) | Thinkware customer support acknowledged receipt, confirmed the report was forwarded to their development team. No technical response, timeline, or fix confirmation was provided. |
| 2026-07-21 | 30-day disclosure window closed. No further vendor contact received. |
| 2026-08-10 | Public disclosure |
 
## What's Deliberately Not Included Here
 
Consistent with responsible disclosure practice, this repository documents the *existence and impact* of each primitive without providing a ready-to-use exploitation tool:
 
- No working `PUT_FILE` proof-of-concept script is published. The reproduction steps above are sufficient to confirm the finding; a parameterized, ready-to-run write-anywhere tool would offer no additional value to legitimate verification while providing real value to misuse.
- No investigation was made into whether files placed via `PUT_FILE` can be executed, or into further exploitation chains.

## Tooling
 
These findings were confirmed using [`u3000py`](https://github.com/turretsec/u3000py), an open-source Python client for the U3000's control protocol, built as part of this research.
 
- `u3000py`'s `ThinkLinkClient.download()` method is a direct, runnable reproduction of Finding 2: `cam.download("/tmp/wpa_supplicant.conf")` reads the device's live WiFi configuration with no restriction.
- `ThinkLinkClient.get_wifi_info()` is a direct, runnable reproduction of Finding 3 (the real password is redacted by default in any printed output; the real value is still accessible on the returned object, matching how the finding itself works).
- `u3000py` deliberately does **not** expose a general-purpose `PUT_FILE` capability (Finding 1), for the reasons noted in that finding's writeup.

## Credits
 
Discovered and disclosed by Ryan Moore ([turretsec](https://github.com/turretsec)).

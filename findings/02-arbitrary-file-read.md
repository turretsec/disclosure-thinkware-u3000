# Thinkware U3000: Unauthenticated Arbitrary File Read via `GET_FILE`/`LS`
> **CVE:** CVE-2026-101054 ([VulDB #410916](https://vuldb.com/vuln/410916))

**Date:** June 2026

**Affected device:** Thinkware U3000 dashcam

**Affected component:** TCP control protocol, command socket port 7878 / data socket port 8787, with no authentication and no TLS

**Firmware tested:** v1.02.04 (current production release). Also separately confirmed on v1.02.00 prior to upgrading. Re-tested specifically after the upgrade to rule out a silent fix; behavior is identical on both.

> **Note on affected model:** all findings below were confirmed against the base Thinkware **U3000**. Thinkware also sells a separate "U3000 Pro" variant; whether it shares the same protocol implementation has not been tested.

## Summary

`LS` (`msg_id` 1282) lists the contents of any absolute path on the device's filesystem with no restriction, and `GET_FILE` (`msg_id` 1285) reads the full contents of any absolute path back over the data socket, also with no restriction. Together these allow any unauthenticated network client to enumerate and read arbitrary files on the device, not just recorded video, but system files. Confirmed by reading the device's `/tmp/wpa_supplicant.conf` (its live WiFi configuration, containing the real SSID and password for the network it's joined to) directly, with no special access beyond normal use of the documented `GET_FILE` command.

This is the **read-side** of the separately-filed `PUT_FILE` arbitrary-write finding.

## Relationship to the other WiFi-credential finding

This is **not** the same finding as the previously-documented `GET_STATUS "wifi_info"` plaintext credential disclosure, even though both expose the same WiFi password. They are mechanically distinct:

- `GET_STATUS "wifi_info"` is a single, dedicated status query that happens to return credentials as part of its designed response shape.
- This finding is a *general-purpose file-read primitive* with no awareness of what it's reading. It returns the credentials file with the exact same lack of restriction it applies to any other file on the device.

A vendor fix to one (e.g. redacting the `wifi_info` response) would not fix the other. They're filed as separate candidates for that reason, while both ultimately trace back to the same architectural cause: no authentication anywhere on this protocol.

## Reproduction steps

1. Complete the standard session handshake (`START_SESSION` -> `SET_CLNT_INFO` -> `APP_CONNECT`).
2. `LS` on `/tmp` confirms `wpa_supplicant.conf` is present, alongside other real system files (`hidraw0.sh`, `aws.dat`, `resolv.conf`, etc.), already observed incidentally during the `PUT_FILE` testing in the companion writeup.
3. `GET_FILE` with `param: "/tmp/wpa_supplicant.conf"` returns the file's real size, then the full file content streams over the data socket exactly as it would for a video file.
4. The returned content contains real `ssid=`/`psk=` lines matching the camera's actual configured home network, confirmed directly, not inferred.

## Impact

Any device that can reach the camera on its local network can read:

- The complete recorded video library (already a known consequence of this protocol's lack of auth, now formally tied to this specific primitive)
- The live WiFi configuration file, including the plaintext password, a second, independent route to the same credentials as the `wifi_info` status query
- Any other file on the device's filesystem, system or otherwise, that `LS` can enumerate

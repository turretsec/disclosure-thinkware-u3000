# Thinkware U3000: Plaintext WiFi Credential Disclosure via `GET_STATUS "wifi_info"`

**Date:** June 2026

**Affected device:** Thinkware U3000 dashcam

**Affected component:** TCP control protocol, command socket port 7878, with no authentication and no TLS

**Firmware tested:** v1.02.04 (current production release). Also separately confirmed on v1.02.00 prior to upgrading. Re-tested specifically after the upgrade to rule out a silent fix; behavior is identical on both.

> **Note on affected model:** all findings below were confirmed against the base Thinkware **U3000**. Thinkware also sells a separate "U3000 Pro" variant; whether it shares the same protocol implementation has not been tested.

## Summary

`GET_STATUS` with `param: "wifi_info"` (`msg_id` 2050) returns the camera's WiFi SSID and **plaintext password** to any client on the same local network, with no authentication and no pairing step. Three lines of Python (`START_SESSION` -> `APP_CONNECT` -> `GET_STATUS wifi_info`) are sufficient.

## Relationship to the other WiFi-credential finding

A second, mechanically distinct finding (filed separately; see [02-arbitrary-file-read.md](./02-arbitrary-file-read.md)) reaches the same credentials by a different route: `GET_FILE` reading the device's `wpa_supplicant.conf` directly, with no path restriction at all. That finding is a general-purpose file-read primitive that happens to be able to read this file among any other; this finding is a single, dedicated, designed status response that happens to include credentials as one of its fields. Both were confirmed independently. A vendor fix to one would not necessarily fix the other.

## Reproduction steps

1. Complete the standard session handshake (`START_SESSION` -> `SET_CLNT_INFO` -> `APP_CONNECT`).
2. Send `GET_STATUS` with `param: "wifi_info"`.
3. Response is `{"rval": 0, "msg_id": 2050, "type": "wifi_info", "param": [{"ssid": "<real SSID>"}, {"password": "<real plaintext password>"}, {"mac": "<real MAC>"}]}`.

## Impact

Anyone within range of the camera's network (or anyone who can otherwise reach it, e.g. if the camera is in AP mode, simply anyone in WiFi range at all) can retrieve its WiFi password without needing to already know it. This is a direct escalation path: knowing this password grants the same network-level access needed to exploit the other two findings (`PUT_FILE` arbitrary write, `GET_FILE`/`LS` arbitrary read) in the first place, in scenarios where an attacker doesn't already have that access.
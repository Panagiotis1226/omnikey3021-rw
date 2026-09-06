# Access-control design

The `access` layer turns the reader into a badge-enrolment station and a door
controller.  It works with the cheap memory cards (SLE 4442) most people buy for
contact access systems and with ISO 7816 CPU cards.

## Credential block (64 bytes)

```
 0  4  "OK3A"                 magic
 4  1  1                      version
 5  2  site code              big endian
 7  4  card id                unique per card, also the registry key
11  4  issued                 unix time
15  4  expires                unix time, 0 = never
19  1  access level           matched against schedules
20  1  flags                  01 active, 02 temporary, 80 admin
21 11  reserved (zero)
32 32  HMAC-SHA256(site_key, bytes 0..31 || binding)
```

* **Memory cards**: stored at address 32 (`--mem-offset`) in the SLE 4442 user
  area, so bytes 32..95.  *binding* = bytes 0..31 of the card (manufacturer/issuer
  area).  `--protect-binding` sets the irreversible protection bits on that area
  so nobody can rewrite it later.
* **CPU cards**: stored in transparent EF `0001` (`--iso-fid`), optionally inside an
  application (`--iso-aid`), written after `--iso-pin`.  *binding* = GET DATA 9F7F
  chip serial when the card supports it, otherwise the ATR.  With
  `--iso-challenge` the door additionally runs GET CHALLENGE / INTERNAL
  AUTHENTICATE with a per-card key `HMAC(site_key, "iso-auth" || card_id)`; the
  applet on the card must answer `HMAC-SHA256(card_key, challenge || serial)`
  (the simulator's ISO card does exactly this).

## Decision sequence (`AccessController.check`)

1. read block + binding (unreadable -> deny)
2. blank -> deny "not enrolled"; bad magic/version -> deny "invalid"
3. HMAC over header+binding must verify (forged, copied, wrong site key -> deny)
4. site code, active flag, expiry
5. registry: card known, not revoked, id matches, holder active
6. schedule for the access level (no schedule = always allowed)
7. optional CPU-card challenge/response
8. log the event (all outcomes are logged in `events`)

## Threat model - be honest with yourself

| Attack | Memory card (SLE 4442) | CPU card + challenge |
|---|---|---|
| Edit fields on a card | HMAC fails | HMAC fails |
| Copy block to another blank card | binding differs -> fails | serial differs -> fails |
| Bit-for-bit clone incl. manufacturer area | **succeeds if the attacker can write bytes 0..31 of a blank card** (most retail SLE 4442 ship with those bytes unprotected). Mitigation: keep the manufacturer area protected on issued cards (`--protect-binding`) and rotate site keys; accept the residual risk for low-security doors | fails: the key never leaves the card |
| Stolen card | revoke by card id | revoke by card id |
| Stolen site key | full compromise: re-issue all cards | same |

Store `site.key` with the same care as a master key.  The controller PC should
run `access monitor` from a service account that can read the key and database
and nothing else.

## Wiring it to a door

`access monitor --exec 'CMD'` runs a shell command on each grant with placeholders
`{card_id} {holder} {granted} {level}`, e.g. a GPIO pulse for a relay, `curl` to a
door controller, or a serial write.  `--webhook URL` posts the JSON decision.
`access monitor` loops: wait for card -> connect -> decide -> callback -> wait for
removal, so a card left in the slot opens the door once.

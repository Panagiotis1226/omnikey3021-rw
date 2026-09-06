"""Use the reader the way HBCI software does: CT-API + CT-BCS, here over PC/SC (no vendor library)."""

from omnikey3021 import ctapi

api = ctapi.PcscCtApi()                       # or ctapi.NativeCtApi("/path/to/libctapi.so")
assert api.CT_init(1, 0) == ctapi.OK
atr = ctapi.request_icc_and_reset(api, ctn=1, pn=0, timeout_s=30)
print("ATR:", atr.hex())
rc, dad, sad, resp = api.CT_data(1, ctapi.ICC1, ctapi.HOST, bytes.fromhex("00A40400"))
print("SELECT ->", resp.hex(), ctapi.RETURN_CODE_NAMES[rc])
api.CT_data(1, ctapi.CT, ctapi.HOST, ctapi.ct_bcs(ctapi.INS_EJECT_ICC, 0x01, 0x00))
api.CT_close(1)

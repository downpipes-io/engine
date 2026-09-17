// Compile-time vendor pins.
//
// The licence check verifies a customer's out-of-band, vendor-signed assurance grant (LICENCE_TOKEN)
// against the vendor's PINNED public signer key. That public key is the SAME for every customer and
// never changes across renewals, so a customer should never have to pin it themselves, and a brief
// secret-propagation window (env not yet populated) should not produce "pinned vendor key not
// configured" during a live demo. This file is where the vendor BAKES that public key into the build
// at release time, so a stock engine verifies a licence with no LICENCE_SIGNER_PUBLIC env var set.
//
// PRECEDENCE: an explicit, non-empty env.LICENCE_SIGNER_PUBLIC still WINS over this baked default (so a
// self-host can pin their own signer, and the demo, which sets LICENCE_SIGNER_PUBLIC, is unaffected).
// See effectiveSignerPin in src/admin/licence.ts. This baked pin is the fallback used only when the env
// override is absent/empty.
//
// SAFETY: this is the verify-only PUBLIC key, the public twin of the control-plane's private signer.
// Baking it grants no access to anything: it can verify a licence but cannot mint one, cannot touch
// data, and cannot gate the data or recovery path (the licence is fail-open by design; see licence.ts).
//
// =============================================================================================
// DEFAULT_LICENCE_SIGNER_PUBLIC, THE ONE PLACE THE VENDOR PINS ITS REAL LICENCE-SIGNER PUBLIC.
// =============================================================================================
// FILLED (the bake is ACTIVE): the value below is the vendor's real licence-signer public, verified
// byte-identical to the canonical licence-signer-public.json in the vendor's offline live-keys before
// it was baked. A stock engine therefore verifies a licence with no LICENCE_SIGNER_PUBLIC env var set;
// a non-empty env override still wins (effectiveSignerPin), and licence handling stays fail-open.
//
// The value is a single base64url string of EXACTLY 2624 bytes: ed25519(32) || ML-DSA-87 public(2592),
// the same layout parseVerifier expects and the same 2624-byte layout as UPDATE_SIGNER_PUBLIC.
//
// HOW IT WAS DERIVED: it is the PUBLIC twin of the control-plane's DOWNPIPES_LICENCE_SIGNER_PRIVATE. The
// deployed control plane's own admin surface reports it (see docs/CONTROL-PLANE.md): GET
// /admin/signer-public returns { licenceSignerPublic }, and a POST /admin/licence mint echoes the same
// value alongside the minted token. It is PUBLIC and CONSTANT across renewals and across every customer,
// so it does not change between releases unless the vendor rotates the signer key itself.
export const DEFAULT_LICENCE_SIGNER_PUBLIC: string = "uq5Tkw9Ko1uJ_d2l3DtkX4xDhUGGuSk626V3Qy70yI6njfKGvn8vzc9Y3HmogoD5HbMf6bXRc_MZRM57wJTAoYtrkhVxsaUWS-Q8wm4s_e2EDrxF4Lwv2p5gDgLB-CnA_grEyg5BFrJFh0wbHy0F5Y3tBLVsaae99e1lD-X_pfnzh0v7b3fbHfbRFlVXN6hVMZEZ7FZI7jcnPYRxJZUFcjq67wRLVgpP-2sn1yf8uBQcbc5KqUtHYJswBoRb3dPKQebI_xo1bZId2gtwbr-ewdrnL5h0USdZZUh1XiSaIudUWNz_TolXEgKROHyj8l2-gmB-K1OB9QWcVtyGrIE8WnkkG65oh0VHF0a_VMZLd870iqCH_qWydHgHs4AmLC1GGvOCqn_gmYYzWsqpv6IKa72MyrSOA6xb1qHRL1YL1Is8h4-ckzo8ii_UqhiS0Wo0ln_RTmmmAHC_BNxOUYcJezulcnBy2B-yYbd_LWkvkIWZEIBDH9BnqceSQ5MRANI08WiH09xVCJJOa3dMT5GP13Ez14MLKPxp-IhHv4omxdeiiZlt1NzheFWrNSJmx7ijxmnbstlZaIODw7DF8Ztm1yuxvPMcFXGxTKysivOpEvAAvrAUGVz2sUd0cXsYfgKN0RD3XyUvSrkoLD9YZFtq1l0Zf3KQXAQcyfjuIlsnEoYHrlF2a32uaOUI2QFlbS7T0BmEul435t-NP8juRdWgJto0DiL2qEvxy-vxiBAAfYkBqwV1fH8ssEOsarl-TjUm9yxDUVk9Vxz2rYwCxEO4uakGeaVd9xwr0w85qkyyQigWhTv2Tz8x9lBanKYeoO7GhW62XSG0fodgIX1bLsvCyZNGK9KcBifj5mg8g-FkBLGkrB2A-g_rYm8K8NuEtTtJaQCIvkbn615lwQaJ6vzVYJ-6EkKyPFHSP3xbWIEfLfkBe9RNsSt9mH6HyH8Oqnouh0E3upMmoulOapiyK0e2YToUkr3e-GPXnLv82tEd14bGlxbaNVu3HZapI19cnfvtT8xbNi3eICUMfSSdzDhO3unKbeYMtYtVBlPcPCfCur7ePL0P89Tez51o-fbGd-WiWMxUNj8v1GfOZD7uqjVA_IRoki0lM-f9lHygv7c9tVUp8zv5SNSOXXpuZbSSgMzxDqg5LuqsuVvzld3RCN4b4Zu8ETKGOohWT2-fHZh2iFXg23zaDIx-pPaaGcFSO7-weV5WJvXjV0vufIyn5QfRJieC4Cn7fcqRsu07ly0HrzwxQnqy4I2kiRwES9Qc47yAPPlZU9eGDSQ_QqcZHfoEpFfJFdPoKpUjaWhXK48EuXACS0KPcVlil96g7k6YsDpdTZ3dGjmLtmiLyNuzQBaqCxQrATGNwOHIbacf6DKMJ1vk3wFcBoFEcjdXzDVHtS6qWae8FnOlg5cG8ShH1bJu6-PoXfxrbVsGDSbB8OE7sqnQs6el3-TdWf3Z-vFQnfg8Fx43a8zzPAn4gVbOYDiIaNxYX_szRudQmruW0ai79bc7QrM0qYIOGSbQbSs0njAMfSDpPhJN93ZOzcawlOMsFS-ABWlJe9ZYUqrKTildYvTE4jDitikZyeJsPf69pX7AdaKPnnOU6z27NPsftWp6OOPMi_tUe9M6fp7ad2_TvI8k5ugwH9ztscPSkjBrPxZSX3vxVfPIbEjbAiyIY0gUe5Tq7O1_0j9jRpE85RKwvYzQJHG1UfcjI5Py_axN-FHp6DvuiUGa5R73ttNoG89ncKx8paqzTnMbtnz97ydtuwR5QWwyf4QcnIwBU7afI6hBVtnfDd2zMSGPobKgvYfGMcZobVEB4P6H7dB1CjVvxljWwkP9Bj3fmH6vkyQTRX4rXJbwanEPW2XG-uBN4A6VvzI0WfB2Zr4SHMEUIXT3Eg_MYE0K_pGIP6wgbFrDLMqRK42S_SLepFvQH47S0NFoJThyXil6YCfDjiasiUjrzduLl2fqZbOU5BqK6niSrSPZ4TT7zbhvc8qrdbJm2h9AJwiDwDdIXEDTnIpkPIsJW0Qdqv2wxQ0cl9TpINaycX-E470ddcMmTkn_9Sfu9R8xSbwWPMUOS2hmOETl7Zbrdlq1Edj2I_bpmOXLZB7Ftqvp2ov-D_js2Mp_yrPNRv15JabALV-SnuPrdFO_83JDgtFShoQlO2OPIHXkuIGJZ6duWjkLnceaXY_czK1yGdKq49yM93jhdJ_5_H7G6YRVj8YIwdSM5V8d8Jj62xmL0eAPg8sruOBQug-pTaDN4JLAHEbKXfE3GpOjm2ndVX8LX65R6r6p6Ww_w4BNfiIzP_5nod0wLR984v5TRgV36N_2_ZlAGm1MVwF03_YQt8QuLju0TycPGrLWjLdePVMJKZQ1BuVJ_XA1SC-oOibbye6IXNuce3qOVoMjLirdlMtPcPDAFtowpJNulF3tBhNCT1rcHm2Q-ceZeaEl8zntEYO8_Deh09lMjJR5VKOzeGEpKwuZZul1qjuWPrhMVIBkbWugG8tO8lQU1KkH3AuRlFhSCZhM9xU5JJQ1w6wREnHNW5Tj9lGBUcs0Xf7lDKTYjX6bz_07WsIm48ohZWF0dKD950q5oNVQlORVggPYXW425pjH96y0eHU3XS0YQzUOScjNwW15QQ1qBp6TPtFupnpZFLY-_rLfMTvXXu2QSH7yLtHOexpTbb-6SySdmMcK4WWZNSKzhiw5vrEluH_S-XpGfvrU-dTb_nWGPI-sshD8jmUVDDIAFp-MZugWRdZlXdizSn_cSEEvxp2fqXHCGtgovGsYo5LNdTelHKJByopLsRT657JhXuBB74GFVjOWALUloG7-_5OK6L4wO9xB_BSaelDl4B14cZx_PAFQ08C-_t1sgXMHDDnMmeCbos1w3TKF9k4_9ajBUk66hun7KpP_6CjCq8EuZ09v1noq5gOreDZhng6mT1Mj1wA-EVxGK8eTbDi-Gj8aT8jDuFHLUnUTc7O-XcJfQ0JAJGzmNdT4Vp-60pjeJ-_infhusYQUHmuesCpyRUYpmAkphrvsdAccHsBcBh8BxCaVAPtLzVGMjJ3-pDNLVmcUxdFdhnvCcjJ0UxjH5Y3W31a5vvZ3XLk6fxAJr7R36PSVMZtHojU2CVKXOb0ux2rk42GvHcgAn1HOiKfp7eoaUtJVudSfKTyYKJ5fSGquH3gXwgXL0VmR_Ohq3zDgYOIqQU8oAY4F1_RPfRcNy0F6p7oCmhLWEYZFu_zE3E737q7HvjKwXUDK5WokeyhXkiUbbglENYZV-beywIUQ5EZQmtdO2t13GgGaj1HOmDTvES93a34j37TuqQA8YTK02VBx8GfwZ1_nfQ4ssipCdKFfcq5l176D3BtxoggowEsf88ZhjkRqn0lbwb5CmY7OOPeH1p5qZ0Ah6Q6S5GTObT3SW1euLTJO5Nxyk8ArNSpp5eAgZZpXjkgEZSAToY3xEV_ADnYXMj_SxYU0Nf8FKdzDNb0hZYvqor6zBFf_xUP2n0z4-e-OHCfsT9E";

// NOTE (out of scope here, intentionally not implemented): the update-channel pin (UPDATE_SIGNER_PUBLIC,
// the release-signer the safe-apply channel signature is verified against) is the same vendor-pin
// pattern and could follow the same baked-default approach (a DEFAULT_UPDATE_SIGNER_PUBLIC here, with an
// effectiveUpdateSignerPin env-override helper in updates.ts). It is deliberately left alone to keep
// this change scoped to the licence pin; the update channel also requires UPDATE_CHANNEL_URL, so a bare
// baked update-signer would not by itself enable anything.

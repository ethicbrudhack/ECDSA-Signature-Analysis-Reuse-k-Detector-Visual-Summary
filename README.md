# 🚀 ECDSA Signature Analysis & Reuse-k Detector — Visual Summary

This script performs a compact set of ECDSA vulnerability checks on a small collection of signatures `(r, s, z)`.  
It looks for common real-world issues that lead to key compromise: **reused nonce (`r`)**, **Low-S** signatures, and **linear nonce relationships**.  
If a repeated `r` (nonce reuse) is found, the script attempts an immediate algebraic private-key recovery.

---

## 🔎 What it does (high level)

- Scans a list of ECDSA signatures for **identical `r` values** (indicating the same nonce `k` was reused).  
- If reuse is detected, computes private key `d` from two signatures with the same `r` using the closed-form formula:  
d ≡ (z1 − z2) * (s1 − s2)⁻¹ (mod n)

- Detects **Low-S** signatures (`s < n/2`) which may be non-standard or weak.  
- Attempts to detect **linear dependence** between nonces by forming symbolic equations `s_i * k_i − z_i = 0` and solving them.

---

## 🧩 Visual Flow



Input: list of signatures (r, s, z)
↓
find_reused_k() ←───────────────┐
(group by r) │
↓ │
if reused pair found → recover_private_key()
↓ │
compute d = (z1 - z2) / (s1 - s2) │
↓ │
output hex(d) ────────────┘

Additionally:
detect_low_s() → list of indices with s < n/2
detect_linear_k() → symbolic solve for k0..kN (if solvable)


---

## 🧠 Mathematical Notes

- ECDSA signing equation (mod n):  


s = k⁻¹ (z + r·d)

If two signatures share the same `r` (same k), rearrange the two equations to eliminate `k` and solve for `d`:


d ≡ (z1 − z2) * (s1 − s2)⁻¹ (mod n)

Requires `(s1 − s2)` invertible mod `n`.

- **Low-S**: Standard practice requires `s` to be in the upper or canonical half of the group; low `s` can be a sign of non-standard signing or malleability handling.

- **Linear k detection**: sets up symbolic linear equations `s_i * k_i = z_i` and attempts to solve. Useful if nonces follow a deterministic linear model.

---

## ⚙️ Usage & Output

- Run the script (it already contains example signatures in the `ecdsa_signatures` list).  
- Console outputs include:
- `⚠️ Reused k in signatures: [...]` and recovered private key if successful (`🔑 Odzyskany klucz prywatny: ...`)
- `⚠️ Detected Low-S in signatures: [...]`
- `⚠️ Detected linearly dependent k: {...}` (symbolic solution, if any)
- `✅ Analysis complete!`

---

## ✅ Practical Use Cases

- Quick auditing of a small set of signatures extracted from blockchain data.  
- Reproducing academic examples of nonce reuse exploits.  
- Pre-filtering signature sets for deeper recovery attempts (brute-force or ML-guided).  
- Educational demonstration of how ECDSA nonce reuse leads to key recovery.

---

## ⚠️ Limitations & Caveats

- The script assumes **exact** repeated `r` values for reuse detection — near-miss / nearly-equal r requires different methods.  
- Private-key recovery works only if `(s1 − s2)` is invertible mod `n`. Degenerate cases are skipped.  
- Symbolic linear solving scales poorly; for many signatures it may be infeasible.  
- Example signatures are static — adapt the `ecdsa_signatures` list to your dataset.

---

## ⚖️ Ethical Reminder

This code is for **research, auditing, and education only**. Do **not** attempt to recover private keys or access wallets you do not own or have explicit permission to test. Unauthorized key recovery is unethical and illegal.

© 2025 — Author: [ethicbrudhack]

BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr

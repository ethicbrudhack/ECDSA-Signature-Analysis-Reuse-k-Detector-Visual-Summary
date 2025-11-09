from collections import defaultdict
from sympy import symbols, Eq, solve
import hashlib

# Lista transakcji ECDSA (r, s, z)
ecdsa_signatures = [
   {"r": int("d8e2d92d3fca2a3293ed2e57c80a8db40069da2229225756b77de2f967baa1fb", 16),
         "s": int("6f2dc5ce39475b4c98ae27285a36939aadf19e38b3845c57400ef08326d24d23", 16),
         "z": int("cc5260cf9f0c439f2847dae4560a63f62da6fb6682ed77df872076f0f0aafd34", 16)},

        {"r": int("5ebecec888b158797ded9ebc1421b4797d4077c2e16945f45361ac33f6abf41b", 16),
         "s": int("340050758fd9de606d45383f63f1b236a7a47318c595e99c910f4b943a88a364", 16),
         "z": int("5429e50aa800fe787d59bc03594476c704c86ce7b58060025ffe9ee6c2658273", 16)},

        {"r": int("c1c83fb6cf745bf4eb518b4683dadb2e6eeab031fde8f7f27ff0da49a182d317", 16),
         "s": int("044812973948efef2db516c93f7eb4ee8d224ccc0181d3794fc3704ae3324a8b", 16),
         "z": int("ac6ede455f205ac41a75ce9f1a88cc625a11a3e6b377531096074cbcdbf97a67", 16)},

        {"r": int("4122285f136a320f7c703b3e426c59238918d9109e7c3941fc6a0b6adf5207f7", 16),
         "s": int("1e93eb84918f74f5a26d32366907af8c6ab9e1942b9efb6d935dbe178d06e9ff", 16),
         "z": int("19b517590993c4c3c4a39a516b97eefb1f65c81be9ba251c34a573632b8ba654", 16)},

        {"r": int("bde208ab14f08c144c476ad0913b819ac85edb0817648f7a9c7bfba6ff3d2ae4", 16),
         "s": int("361cd7453471392f166f75fae077c6eab3bb87b3cf097e6c8e821b647adfa2c8", 16),
         "z": int("c2aed3ced357dea4d71da93173fe5fcdf9a3ffa5f2112c6c0d7268483aefe916", 16)},

        {"r": int("d49081dbc8456347d95a13f012f952ba515c3a2d7e6a217a45d524231f9e73be", 16),
         "s": int("129b6d94862d072a25c381264f280ed4a72d6a6e72d14971d0d7be4339c91893", 16),
         "z": int("6fcff0a703f2af14a94588598762ac7920a75be3cf51bba530d54b3ae1482ff1", 16)},

        {"r": int("27c90531406bbf08bd6325b06fe0ac32e61a66f3d8b2762a7bf2ac6c13e76ddc", 16),
         "s": int("096ddba45472fe9cca48753e7ca89b70ef358badbd458e08ef77fc79a85d7ae8", 16),
         "z": int("c29d8e7add11ca847ca90aebc44821571aa0224609a534374aedb3680a663b9e", 16)},

        {"r": int("ba4cbf9de2d8f8cec6ace7fd8fde68b6bb247a3494618f0684a07542557d8dd1", 16),
         "s": int("6a8dd246334494bbb852c19e885af8b951e90983438cd6eef7daf01ba2a21453", 16),
         "z": int("639a5415a446859710e6e65b6ece3731a74be0e3a8a7486c95c01b32b410ebd8", 16)}
]

# Parametry krzywej secp256k1
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # Porządek krzywej

def find_reused_k(signatures):
    """ Sprawdza, czy występuje to samo r (czyli ten sam k) """
    r_values = defaultdict(list)
    for i, sig in enumerate(signatures):
        r_values[sig["r"]].append(i)

    reused_k = [indices for indices in r_values.values() if len(indices) > 1]
    return reused_k

def recover_private_key(signatures):
    """ Odzyskuje klucz prywatny, jeśli r jest powtórzone (reuse k) """
    reused_k_indices = find_reused_k(signatures)
    
    for indices in reused_k_indices:
        i1, i2 = indices
        sig1, sig2 = signatures[i1], signatures[i2]
        
        # Rozwiązanie dla d = (z1 - z2) / (s1 - s2) mod n
        z1, z2 = sig1["z"], sig2["z"]
        s1, s2 = sig1["s"], sig2["s"]
        r = sig1["r"]  # Ten sam r
        
        if (s1 - s2) % n != 0:
            d = ((z1 - z2) * pow(s1 - s2, -1, n)) % n
            return hex(d)  # Klucz prywatny odzyskany!
    return None

def detect_low_s(signatures):
    """ Sprawdza, czy S jest małe (powinno być > n/2) """
    low_s = []
    for i, sig in enumerate(signatures):
        if sig["s"] < n // 2:
            low_s.append(i)
    return low_s

def detect_linear_k(signatures):
    """ Sprawdza, czy k są liniowo zależne """
    equations = []
    k_symbols = symbols(f'k0:{len(signatures)}')

    for i, sig in enumerate(signatures):
        eq = Eq(sig["s"] * k_symbols[i] - sig["z"], 0)
        equations.append(eq)

    solution = solve(equations, k_symbols)
    return solution if solution else None

# --- URUCHOMIENIE ---
print("🚀 Sprawdzanie ataków ECDSA...")
reused_k = find_reused_k(ecdsa_signatures)
if reused_k:
    print(f"⚠️ Powtórzony k w podpisach: {reused_k}")
    private_key = recover_private_key(ecdsa_signatures)
    if private_key:
        print(f"🔑 Odzyskany klucz prywatny: {private_key}")

low_s = detect_low_s(ecdsa_signatures)
if low_s:
    print(f"⚠️ Wykryto Low-S w podpisach: {low_s}")

linear_k = detect_linear_k(ecdsa_signatures)
if linear_k:
    print(f"⚠️ Wykryto liniowo zależne k: {linear_k}")

print("✅ Analiza zakończona!")

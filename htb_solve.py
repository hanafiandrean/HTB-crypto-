import os, sys, json
from functools import reduce
from pwn import process, remote, context

from py_ecc.bls.ciphersuites import G2ProofOfPossession as bls
from py_ecc.bls.g2_primitives import G1_to_pubkey, pubkey_to_G1
from py_ecc.bls.point_compression import decompress_G1
from py_ecc.bls.typing import G1Compressed
from py_ecc.optimized_bls12_381.optimized_curve import add, G1, multiply, neg, normalize, Z1

from sage.all import EllipticCurve, GF, identity_matrix, PolynomialRing, Sequence, zero_matrix, ZZ

context.log_level = 'info'   # 'debug' kalau mau lebih verbose
context.timeout   = 10       # cegah hang lama saat recvuntil

# --- IO utils ---
def get_process():
    if len(sys.argv) == 1:
        #ganti path server lokal jika beda
        return process(['python3', 'crypto_blessed/challenge.py'], level='DEBUG')
    host, port = sys.argv[1].split(':')
    return remote(host, int(port))

def sr(io, data: dict):
    io.sendlineafter(b'> ', json.dumps(data).encode())
    return json.loads(io.recvline().decode())

def recv_prompt_and_send_C(io, C_pk_branch, C_g1_branch):
    """
    Tunggu prompt C, kirim C sesuai varian:
      - '... C = x * pk (hex): ' -> pakai C_pk_branch
      - '... C = x * G1 (hex): ' -> pakai C_g1_branch
    Return buffer prompt (buat debugging kalau perlu).
    """
    buf = io.recvuntil(b'(hex): ')
    if b'x * pk' in buf:
        C = C_pk_branch
    elif b'x * G1' in buf:
        C = C_g1_branch
    else:
        #fallback: pk-branch (umum pada source asli)
        C = C_pk_branch
    io.sendline(bytes(G1_to_pubkey(C)).hex().encode())
    return buf

# --- EC / LCG crack ---
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
K = GF(p)
a = K(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
b = K(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
E = EllipticCurve(K, (a, b))
Gp = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
       0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
E.set_order(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 * 0x1)

def crack_ec_lcg(values):
    #values: [u1,v1,u2,v2,u3,v3] dari 6 robot_id << 32
    assert len(values) == 6
    u1, v1, u2, v2, u3, v3 = values
    a1, b1, a2, b2, a3, b3 = PolynomialRing(K, 'a1, b1, a2, b2, a3, b3').gens()

    ec1 = (v1 + b1)**2 - (u1 + a1)**3 - a*(u1 + a1) - b
    ec2 = (v2 + b2)**2 - (u2 + a2)**3 - a*(u2 + a2) - b
    ec3 = (v3 + b3)**2 - (u3 + a3)**3 - a*(u3 + a3) - b

    ec4 = ((u1 + a1) + (u2 + a2) + Gp.x()) * ((u2 + a2) - (u1 + a1))**2 - ((v2 + b2) + (v1 + b1))**2
    ec5 = ((u2 + a2) + (u3 + a3) + Gp.x()) * ((u3 + a3) - (u2 + a2))**2 - ((v3 + b3) + (v2 + b2))**2
    ec6 = (Gp.y() - (v1 + b1)) * ((u2 + a2) - (u1 + a1)) - ((v2 + b2) + (v1 + b1)) * ((u1 + a1) - Gp.x())
    ec7 = (Gp.y() - (v2 + b2)) * ((u3 + a3) - (u2 + a2)) - ((v3 + b3) + (v2 + b2)) * ((u2 + a2) - Gp.x())

    A, v = Sequence([ec1, ec2, ec3, ec4, ec5, ec6, ec7]).coefficients_monomials(sparse=False)
    A = A.change_ring(ZZ)
    A = (identity_matrix(7) * p).augment(A)
    A = A.stack(zero_matrix(len(v), 7).augment(identity_matrix(len(v))))
    A[-1, -1] = 2**256

    L = A.T.LLL()
    assert L[-1][-1] == 2**256
    a1, b1, a2, b2, a3, b3 = L[-1][-7:-1]

    W1 = E(u1 + a1, v1 + b1)
    W2 = E(u2 + a2, v2 + b2)
    W3 = E(u3 + a3, v3 + b3)
    return W3

# --- exploit flow ---
def main():
    io = get_process()

    #robot verified
    res = sr(io, {'cmd': 'create'})
    sk  = int(res['sk'], 16)
    rid = int(res['robot_id'], 16)

    #list (butuh signature dari robot verified)
    cmd = 'list'
    sig = bls.Sign(sk, cmd.encode())
    res = sr(io, {'cmd': cmd, 'robot_id': hex(rid), 'sig': sig.hex()})

    ids, Pks = [], []
    for r in res:
        ids.append(int(r['robot_id'], 16))
        Pks.append(decompress_G1(G1Compressed(int(r['pk'], 16))))

    #target kunci 1337 untuk 'unveil_secrets'
    secret_sk = 1337
    cmd = 'unveil_secrets'
    pk  = bls.SkToPk(secret_sk)
    sig = bls.Sign(secret_sk, cmd.encode())
    Pk  = pubkey_to_G1(pk)

    #buat pk' sehingga sum_verified + pk' = Pk
    Pk_prime = add(Pk, neg(reduce(add, Pks, Z1)))
    pk_prime = G1_to_pubkey(Pk_prime)
    assert normalize(add(reduce(add, Pks), Pk_prime)) == normalize(Pk)
    io.success('Forged aggregate public key')

    #join sebagai robot baru
    res = sr(io, {'cmd': 'join', 'pk': pk_prime.hex()})
    new_id = int(res['robot_id'], 16)
    ids.append(new_id)
    assert len(ids) == 6

    #crack EC-LCG dari 6 id
    Wn = crack_ec_lcg([i << 32 for i in ids])
    io.success('Cracked EC-LCG')

    #verifikasi (ZKP) — 64 rounds (x,y dari setiap Wn += Gp)
    sr(io, {'cmd': 'verify', 'robot_id': hex(new_id)})

    for _ in range(64 // 2):
        Wn += Gp
        for c in Wn.xy():
            bit = (int(c) >> 32) & 1
            if bit == 1:
                #cabang "minta x"
                x    = int(os.urandom(16).hex(), 16)
                C_pk = multiply(Pk_prime, x)
                C_g1 = multiply(G1, x)
                recv_prompt_and_send_C(io, C_pk, C_g1)
                io.sendlineafter(b'Give me x (hex): ', hex(x).encode())
            else:
                #cabang "minta (sk + x)"
                sk_x = int(os.urandom(16).hex(), 16)
                C    = add(multiply(G1, sk_x), neg(Pk_prime))
                #prompt C bisa pk/G1 — C sama2 valid untuk cabang ini
                recv_prompt_and_send_C(io, C, C)
                io.sendlineafter(b'Give me (sk + x) (hex): ', hex(sk_x).encode())

    # 8)get-flag
    res = sr(io, {'cmd': cmd, 'sig': sig.hex()})
    sr(io, {'cmd': 'exit'})
    io.success(res.get('flag', 'no_flag'))

if __name__ == '__main__':
    main()
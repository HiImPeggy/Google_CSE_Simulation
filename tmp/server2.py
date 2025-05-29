# server.py
import socket, threading, os
from pqc.sign import dilithium2 as sigalg
from pqc.kem import kyber512 as kemalg
import pyotp
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST = '0.0.0.0'
PORT = 12345

AUTHORIZED = {
    'user1': {
        'dilithium_pk': bytes.fromhex('ade2a221fc446bf1f1739a892bc0e4efe0a76b82bd28f5dc4966cd9ed4f8b0d4f4db4401ba4a322cec3f18ee16667cb8492e19cbf361432e6f0dd03ed4625eedec15369079168cb348f81e3fbb722df330df4f04713ccdfb466d54c8690e6f70b751c36bb2c4c0d999a40b6b30ace2544829c7ba705fe15cbf3b2149154f90a7f032e51da7da2b36d1bea3c6ee7e4d95a9473de220024d9cf7d17428df4b3bd9e12f94b3fcbf76a93401c3db96711773e0a8e261ccd369ab8d7c025c299f4078680a102bba860df05e8217c9d84ccb991a66a3a70ec4a320b524aa05ba89c0be7f0a973fb68b91e6089d7f765632cb5f60ee87af4e2461a89cf0749aa2f4e0a33fc4314845146c7371b9958310b107d3374e678492c29d52b39737d6d00b0a79cc66baa1419d01464b7d64af956e596c872d3f336ebe89bcc6959b72cf3279cc51342acdc3658bba7b14907c768dcbdbe4bbb4b908a0e563e8b9e81ade60758cbaf8e9b870167f4e6907dda609fabfcf619e825dc647e6584227b6d89a547a5667d897fb0b4874598fbf2c00bbbb0b633a363d2ef1f09b98ffa9bc0c66e1777ea0f1004803f4f70461f291d1d5a36f5d3a0714ab9a31aa129fa77077d78b9987c44c52fb68f73acde91b31c9dfb620a5a3d69489d73bb0cece758e2cf2d2a0e3d77bc41d77b7abf5ea86b5ad1e57cb5ae49e780357a90276654eab560adc47ebc13a1e2bfd7fa2773626e18c737fdd83bb59b4c644d2462479db7276771074ab0cc3c747ff71f8a2cbd48e6944c1b643e9e72cfee8b517a6c155f1378b58e08f166a3ef4ee27dd9f0d011825068bcc6da82a51c29b670a5715c14846c52bfe243eeeddcff0fc409ae5dfac88ab90e6f4ddf518a1adaf4837d4ddfff5e9c1bb5be172256edd927d801e1646f690098d44e048fb1e91a4ef6488a74b0fe5edb5ec54f949fa52a1c03ae78362dc14f13d94711f50c670cc5e47935cff6fec0ecfa9f647b7427bc2dc558a4b64d106e4d1002975b234d49cd433cb48881d98eb01b4565563ef8a80c6e300dff7aeddbfde0f7efc709a970f3496697eba24d2a73ba16a5ca0b741baa2b18cc67746d7dad15811a2f00d9ce5fa41cc3929f64f8ef7b1170313735a8c9b7904e008c6534981ad9e5658c56c97070fb83b3a122112573838c783212f076c7abb8223ecb8743762528711472374a87cc237e9812f8343e087ff042da232f6dd37753e4a1508f8ed049e25c366126aae1dde7314eaa825b6a2f109faaacf19f2bc633c86dd4190648e590bba120f9b29dba32eb678ac220885ab7c1d57fc960c57b32eb96d7efb945df7706b6f80051af9bece3f75461c0d40591a17d0781ead0813a2f040893679c4b3fa5c37197d9ffffcfdba475ddd90fb9a5476fde4c3e52707a9e96f0888a16a03fcfb7221470dfbde564ec51602d46e66915330c5d3ca15f79ba56069731a61aa73bf9166f53be98ab01748d65facf8759867117ba308ef31d241d4572b57871c8ca41a0a08c0f3c5db78dfd2a929cfd3e73e63225f38290db035708ba375254a04f153cc83ccbdc7ba30e8cdef21471e7fba55a21b8e94464698d969b256b28652d2ae11dc0a20ef36dfe3556e9cb9c67d7035526bc8471b4ddec70dc8a641432487e008c2517f1f369300ad1704f1cad768795e08d2b7af1f029743586f4e30dd1e8d46d4645c54ba3fa676355f278088b3342ad57a38a63b2f2f3efc9689b7a5421d2ebac445b8b76697089f5d0975fc6a6e1166b8a524d53d6ec73d063505f8f21113859fe81bccccd33010022ee3784a87952be808affdd729b91b86be3af5df4b04e833e2154a0ccaa8afd0'),
        'totp_secret': 'JBSWY3DPEHPK3PXP'
    }
}

def aes_decrypt(key, iv, ct, tag):
    dec = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
    return dec.update(ct) + dec.finalize()

def handle_client(conn, addr):
    print(f"[+] Connection from {addr}")

    # 1. 身分驗證：Dilithium2 + TOTP
    challenge = os.urandom(32)
    conn.sendall(b'AUTH_CHALLENGE' + challenge)

    data = conn.recv(4096)
    ptr = len(b'AUTH_RESPONSE')
    uname_len = data[ptr]; ptr += 1
    uname = data[ptr:ptr+uname_len].decode(); ptr += uname_len
    sig_len = int.from_bytes(data[ptr:ptr+2], 'big'); ptr += 2
    signature = data[ptr:ptr+sig_len]; ptr += sig_len
    code = data[ptr:ptr+6].decode()

    info = AUTHORIZED.get(uname)
    if not info:
        conn.close(); return

    try:
        sigalg.verify(signature, challenge, info['dilithium_pk'])
    except ValueError:
        conn.sendall(b'AUTH_FAIL'); conn.close(); return

    totp = pyotp.TOTP(info['totp_secret'])
    if not totp.verify(code):
        conn.sendall(b'AUTH_FAIL'); conn.close(); return

    conn.sendall(b'AUTH_SUCCESS')
    print("[*] Identity verified")

    # 2. 產生一次性登入金鑰（模擬 KMS）
    session_key = os.urandom(32)
    conn.sendall(b'LOGIN_SUCCESS')
    print("[*] Generated session key locally")

    # 3. Kyber 會話建立
    pk_kem, sk_kem = kemalg.keypair()
    conn.sendall(b'KEM_PUBLIC' + pk_kem)

    data = conn.recv(4096)
    assert data.startswith(b'KEM_CIPHERTEXT')
    ciphertext = data[len(b'KEM_CIPHERTEXT'):]
    shared_secret = kemalg.decap(ciphertext, sk_kem)

    conn.sendall(b'KEM_DONE')
    print("[*] Kyber shared secret established")

    # 4. 開始加密通訊
    while True:
        header = conn.recv(1)
        if not header: break
        iv = conn.recv(12)
        tag = conn.recv(16)
        c_len = int.from_bytes(conn.recv(4), 'big')
        ct = conn.recv(c_len)
        pt = aes_decrypt(shared_secret, iv, ct, tag)
        print(f"[decrypted] {pt.decode()}")

    conn.close()

with socket.socket() as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"[+] Listening on {HOST}:{PORT}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn,addr), daemon=True).start()

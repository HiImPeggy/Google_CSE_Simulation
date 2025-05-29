import socket, threading, os
from pqc.sign import dilithium2 as sigalg
from pqc.kem import kyber512 as kemalg
import pyotp
import boto3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST = '0.0.0.0'
PORT = 8080

# 預先註冊的 client 資訊
AUTHORIZED = {
    'user1': {
        'dilithium_pk': bytes.fromhex('3ab31d75408f8a94feae1c70793899153d2ed157bc1c7f6c121f96ff929ea48280e46b3924600fa40b3b9c3dc52574012b4dd5af515c2e0c9fd83849e54acf5fe997a5b61cf82e8e47840b1446e6a2f823faaf4f9478e537beb7a71a0642c215fc97cab57cf302d421d253615274f72032da444b955ff9b20ef7406373cefc73e576cdec243e72273e28375388b266b4304abacf68caed56619673fe04740bfb50d26171078d10a5c7ee8c9d615ee27fe29cf97968f132b96202ec1c185825a1e181553e60338f2ef5a2bc457d5219878e2e22065d54c683a07273b1a20d3a113c5eb03d9d3248f9a6fd0f6029ba7247febd351ff58ce4a80d13798395c89126094a7a419b91f790ad8e0fe686f8b7ca923440629c7494432b0626b6a86b6472727ec25449822ccdc45b05407c851116a06b75e27337130484eb2e0a8fdf8723caf9befb745b5d060c828b3598f7980b13c6dc2308da6516efb720c080884e67604c4fb3ced22d1d78115bb15539f390d5b3194adbcedc0f9fa4c2a981e378855039f66b8b21879c983630d32c5332ba5dc2d2a16b1a65e6d75f5c2d42898ee80784162d2c3b1a034636d24e7672e4904fc8a0f4b30a6ddd68d359b7e05de11abb9a740385602bf6a517c5a68f635065d9ef015d09a565626072a745cb47da9135607ce591c705b53c6ee09ee86c5d83d0a3a8baaf4f31687cf630e3b5768333a0cbad72f6fe9cc4db2a0b42fd42498b84fc80b589a4cfc432f5ae3e928498adeff5795157732a56068adbf94632acb723e7be0492c1654e2ed88f467179542fd65111410cb1c9bf0112837f1447209a93c38c286cd0b3336970ce8d4805b583e77f38b61df21401c60f7c149f3324fb1bcca65c5a272b192735dc10655cd1efdf35e72881bb5b14a064d09ac3d2b6ffc4abf052ba5f1a92bb6ad33c5430b212f04034e698ea7a57d0eead270648ab11346ad252d02e63b124c94b325cd6910939138d2f47047b6eb39f66e5e451e73bd578823e6b856050a1250b3c1362ee7da8bf7bfef65372d4e317475d466b995f7438234751b33efd50436313814c6746cb5b37d9a32c710b122d1d415ccc662d162861e7b8ff6edb56d06b5ec48fa5287075e92ded02c9ffc9b7d7df5ee00a273c6ebd72187d1909e84e6dc42a8a0cc54b81d996a10a7520477b6dd759a51accaa4573750434b055ec4894d101b92cbe8058c992192bba78ddbe6e1d7329a0c962d7c1fafffbdb4d7b2ea29d83fdc48e9ea79d0f9dff297b74797e903b5e13596294ce7f956ff9963923f9ebb400ca2283233d90de3694bb4cb3acf5c7958809bbccd628f0b5811885bf42868ed20144f8aa02a319052c6e332c2a8fc46335cf534b43ad6fff20101d1b3bc9cdd2c2c2d8763c32cc708791697ec4bf3b5de6865c9f106e4c75ee85cdc6a1d924c46e71655a199ac8e025c99fd1271bc7f72ba6d66095d52464a73763447a9d9d0457e7e835fd10f58c9e08f0dd955a34e59271f09939294524574e4db251c38073ba93408e45271cb7c66216c0a2df13c628a42dad08844206c55456d236be1d02e67d175fa349e100816a64e25483abe5344bc5fc682a7ab3d81466f601cfe3d19dd51d6162b2cb7c66b42658d1d8ab8eb94a67a72af4b9506d438d7df0d829fdd4b58bc89ee5488ac32fc11de65f12d33b059e03161cc3003db12e958dcf7d8e19fe665d1722a42f22cde527e032a52638e50ae2257ebc35951cdb9ad3f764ab13b5b656f223054e058a9c051d7a38706e63ca34fb11237ac4c06b91e01923411dc145d52068bd6e96a8897b3670f716ed2bef44b6093a497855d9ad0bbcfa516b46'),    # hex 格式貼入公鑰
        'totp_secret': 'JBSWY3DPEHPK3PXP'
    }
}

KMS_KEY_ALIAS = 'alias/my-demo-key'
KMS_REGION = 'ap-northeast-1'

def aes_decrypt(key, iv, ct, tag):
    dec = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
    return dec.update(ct) + dec.finalize()

def handle_client(conn, addr):
    print(f"[+] Connection from {addr}")

    # 1. Dilithium2 身分驗證
    challenge = os.urandom(32)
    conn.sendall(b'AUTH_CHALLENGE' + challenge)

    data = conn.recv(4096)
    assert data.startswith(b'AUTH_RESPONSE')
    ptr = len(b'AUTH_RESPONSE')
    uname_len = data[ptr]; ptr += 1
    uname = data[ptr:ptr+uname_len].decode(); ptr += uname_len
    sig_len = int.from_bytes(data[ptr:ptr+2], 'big'); ptr += 2
    signature = data[ptr:ptr+sig_len]; ptr += sig_len
    code = data[ptr:ptr+6].decode()

    info = AUTHORIZED.get(uname)
    if not info:
        conn.close(); return

    # 驗章
    try:
        sigalg.verify(signature, challenge, info['dilithium_pk'])
    except ValueError:
        conn.sendall(b'AUTH_FAIL'); conn.close(); return

    # 驗 2FA
    totp = pyotp.TOTP(info['totp_secret'])
    if not totp.verify(code):
        conn.sendall(b'AUTH_FAIL'); conn.close(); return

    conn.sendall(b'AUTH_SUCCESS')
    print("[*] Identity verified")

    # 2. 從 KMS 取一次性登入金鑰
    kms = boto3.client('kms', region_name=KMS_REGION)
    resp = os.urandom(32) # kms.generate_data_key(KeyId=KMS_KEY_ALIAS, KeySpec='AES_256')
    # session_key = resp['Plaintext']
    conn.sendall(b'LOGIN_SUCCESS')
    print("[*] Retrieved session key from KMS")

    # 3. Kyber512 會話建立
    pk_kem, sk_kem = kemalg.keypair()
    conn.sendall(b'KEM_PUBLIC' + pk_kem)

    data = conn.recv(4096)
    assert data.startswith(b'KEM_CIPHERTEXT')
    ciphertext = data[len(b'KEM_CIPHERTEXT'):]
    shared_secret = kemalg.decap(ciphertext, sk_kem)

    conn.sendall(b'KEM_DONE')
    print("[*] Kyber shared secret established")

    # 4. 加密通訊
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

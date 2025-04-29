from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import requests


def get_confs():
    url = "https://edgeapi.astroapps.io/api/getServersData"

    headers = {
        "key": "pqn_xBDNzoaqsXK6VJHPrHULnk2qMdnJe3oP3BB",
        "host": "edgeapi.astroapps.io",
        "connection": "Keep-Alive",
        "accept-encoding": "gzip",
        "user-agent": "okhttp/4.10.0"
    }
    return requests.get(url, headers=headers).json()['data']


def aes_pkcs5_padding_decrypt(encrypted_b64: str, key: str, iv: str) -> str | None:
    if len(key) != 32 or len(iv) != 16:
        return None

    try:
        decoded_data = b64decode(encrypted_b64)
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
        decrypted = cipher.decrypt(decoded_data)
        return unpad(decrypted, AES.block_size).decode('utf-8')
    except Exception as e:
        print("Decryption error:", e)
        return None

cnt = 0
for each in get_confs():
    cnt+=1
    with open(f"{each['country_name']} {each['city_name']} - {each['type']}.ovpn", "w") as ovpnf:
        ovpnf.write(aes_pkcs5_padding_decrypt(
            each['server_content'], "58EFRql9ICTb+/UJnX-6KDfvReSlm6OP", "y4WnDtruYbwMccqt"))
print(f"Grabbed {cnt} configs")

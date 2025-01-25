import requests
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import os

dirs = ["Premium", "Free"]

for dir in dirs:
    if not os.path.exists(dir):
        os.makedirs(dir)


def get_cypher_key():
    return "khp@@vZoaAD802G9UgCVj0@51C\\4aIQU"


def transform_string(input_str):
    result = []
    for char in input_str:
        if "A" <= char < "[":
            result.append(chr(((ord(char) - ord("0")) % 26) + 65))
        elif "a" <= char < "{":
            result.append(chr(((ord(char) - ord("P")) % 26) + 97))
        else:
            result.append(char)
    return "".join(result)


def fix_conf(conf):
    return (
        conf.replace("resolv-retry", ";resolv-retry")
        .replace("persist-key", ";persist-key")
        .replace("persist-tun", ";persist-tun")
        .replace("status", ";status")
    )


def decode_string(encoded_str):
    try:
        decoded_bytes = base64.b64decode(encoded_str)
        decoded_bytes = json.loads(decoded_bytes)
        iv = decoded_bytes["iv"]
        value = decoded_bytes["value"]
        cypher_key = get_cypher_key()
        transformed_key = transform_string(cypher_key)
        iv = iv.encode("utf-8")
        key = transformed_key.encode("utf-8")
        ciphertext = base64.b64decode(value)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext.decode("utf-8")

    except Exception:
        return ""


all = requests.get(
    "https://papi.fusionsai.net/api/servers?v=2",
    headers={
        "referer": "com.vpn.proxy.unblock.privatevpn.fastvpn.securevpn",
        "key": "84yw7!LhkcIT2TqFPmAd7a8ffO1eJy77",
        "user-agent": "okhttp/4.12.0",
    },
).json()
cnt = 0
for counties in all["servers"]:
    for list_ in counties["list"]:
        if list_["type"] == "premium":
            with open(
                f"Premium/{counties['cname']} {list_['city_name']} {list_['ipaddress']}.ovpn",
                "w",
            ) as file_:
                file_.write(fix_conf(decode_string(list_["server_content"])))
                cnt += 1
        else:
            with open(
                f"Free/{counties['cname']} {list_['city_name']} {list_['ipaddress']}.ovpn",
                "w",
            ) as file_:
                file_.write(fix_conf(decode_string(list_["server_content"])))
                cnt += 1
print(f"Grabbed {cnt} configs")
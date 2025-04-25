import requests
import json
HOST = "https://1249895963.rsc.cdn77.org"
HEADERS = {
    "accept": "application/json",
    "host": "1249895963.rsc.cdn77.org",
    "content-type": "application/json; charset=utf-8",
    "connection": "Keep-Alive",
    "accept-encoding": "gzip",
    "user-agent": "okhttp/5.0.0-alpha.11"
}


def create_acc() -> json:

    payload = {"password": "a7045b5d2f236c1d57", "reseller": "2", "client_version": 222000,
               "lang": "en", "core_version": 28, "deviceid": "android_010ef23d23bd5f3e_M2101K6G"}

    return requests.post(f"{HOST}/v1/user/create", json=payload, headers=HEADERS).json()['result']['username']


def get_locations() -> list:
    payload = {"password": "a7045b5d2f236c1d57", "is_premium": True, "reseller": "2", "client_version": 222000,
               "lang": "en", "core_version": 28, "deviceid": "android_010ef23d23bd5f3e_M2101K6G"}

    response = requests.post(
        f"{HOST}/v1/openvpn/list", json=payload, headers=HEADERS)

    return [i.get('country') for i in response.json()['result']['locations']]


def grab_data(locations: list) -> json:
    confs = []
    for location in locations:
        payload = {"country": location, "client_time": 1, "reseller": "2", "client_lib": "1e2afc,f889eb,841962,c56663,9fdaef,66cd31,b20db5,b3e535,837e72,", "core_version": 28, "deviceid": "android_010ef23d23bd5f3e_M2101K6G",
                   "pkg": "com.vpn.free.hotspot.secure.vpnify", "client_proc": 737041547, "password": "a7045b5d2f236c1d57", "ref": "com.android.vending", "is_premium": True, "nocache": "8a644bcbd9", "client_sz": 148, "client_version": 222000, "lang": "en"}

        confs.append(requests.post(
            f"{HOST}/v1/openvpn/getserver", json=payload, headers=HEADERS).json()["result"])
    return confs


def make_configs(data: list):
    count = 0
    for each in data:
        config = f"""
machine-readable-output
ifconfig-nowarn
allow-recursive-routing
client
dev tun
verify-x509-name {each['expectcn']} name

resolv-retry infinite
nobind
persist-key
fast-io
explicit-exit-notify 1
tun-mtu 1500
tun-mtu-extra 32
mssfix 1336
persist-tun
reneg-sec 0
rcvbuf 2097152
sndbuf 2097152
remote-cert-tls server
replay-window 2048 15
auth SHA256
data-ciphers AES-128-GCM:CHACHA20-POLY1305
verb 3
mute 20
tls-client
tls-version-min 1.2
key-direction 1
connect-retry 10
<auth-user-pass>
{create_res}
a7045b5d2f236c1d57
</auth-user-pass>
"""
        for remote in each["remotes"][::-1]:
            ip = remote["ip"]
            port = remote["port"]
            proto = remote.get("protocol", "udp").lower()
            config += f"<connection>\nremote {ip} {port}\nproto {proto}\n</connection>\n"

        if "tlsauth" in each:
            config += f"\n<tls-auth>\n{each['tlsauth'].strip()}\n</tls-auth>\n"

        if "ca" in each:
            config += f"\n<ca>\n{each['ca'].strip()}\n</ca>\n"
        with open(f"{each['cityname']}.ovpn", 'w') as ovpn:
            ovpn.write(config)
            count +=1
    print(f"Grabbed {count} configs")


create_res = create_acc()
locations = get_locations()
data = grab_data(locations)
make_configs(data)
from pyrad.server import Server, RemoteHost  # RemoteHostもインポート
from pyrad.dictionary import Dictionary
from pyrad.packet import AccessAccept, AccessReject
import logging

def handle_auth(packet):
    logging.info("Received an authentication request")
    logging.info(f"Attributes: {packet}")

    # MACアドレスを取得
    mac_address = packet.get('Calling-Station-Id', [None])[0]

    # 許可されたMACアドレスのリスト
    allowed_macs = ["00-1A-2B-3C-4D-5E", "00-1B-2C-3D-4E-5F"]

    if mac_address in allowed_macs:
        logging.info("MAC address authenticated successfully.")
        return AccessAccept()
    else:
        logging.info("Authentication failed.")
        return AccessReject()

def main():
    logging.basicConfig(level=logging.INFO)

    # RADIUS 辞書の設定
    srv = Server(dict=Dictionary("./radius.dict"), authport=1812, acctport=1813)

    # スイッチごとにRemoteHostを設定
    switches = {
        "10.127.10.51": "TESTKEYAAAAAAAAAAAAAAA",
        "10.127.10.52": "TESTKEYBBBBBBBBBBBBBBB",
        "10.127.10.53": "TESTKEYCCCCCCCCCCCCCC",
        # 以下同様に他のスイッチを追加
    }

    for ip, key in switches.items():
        srv.hosts[ip] = RemoteHost(ip, bytes(key, 'utf-8'), "ex3400")

    srv.BindToAddress("")

    # 認証ハンドラの設定
    srv.auth_handler = handle_auth

    # サーバを起動
    try:
        logging.info("Starting RADIUS server...")
        srv.Run()
    except KeyboardInterrupt:
        logging.info("Stopping RADIUS server...")
        srv.Close()

if __name__ == "__main__":
    main()

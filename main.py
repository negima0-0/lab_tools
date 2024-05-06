from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
import argparse
import os
import time

def clear_screen():
    """画面をクリアする関数"""
    os.system('cls' if os.name == 'nt' else 'clear')

def send_arp_request(target_ip, count):
    while True:
        for i in range(count):
            arp_request = ARP(pdst=target_ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request
            result = srp(packet, timeout=2, verbose=0)[0]

            print(f"Sending ARP Request {i+1}/{count}")
            for sent, received in result:
                print(f"IP: {received.psrc}  MAC: {received.hwsrc}")

        if not query_repeat():
            break


def send_dscp_ping(target_ip, dscp_hex):
    while True:
        ip_layer = IP(dst=target_ip, tos=dscp_hex)
        icmp_layer = ICMP()
        packet = ip_layer / icmp_layer
        print(f"Sending ICMP Echo Request to {target_ip} with DSCP {dscp_hex >> 2}")
        response = sr1(packet, timeout=1, verbose=0)
        if response:
            received_dscp = response.tos >> 2
            print(f"Received ICMP Echo Reply from {response.src} with DSCP {received_dscp}")
        else:
            print("No reply received.")

        if not query_repeat():
            break


def query_repeat():
    """繰り返すか聞く"""
    answer = input("Do you want to send another request? (y/n): ")
    return answer.lower() == 'y'

def main():
    dscp_options = {
        "1": ("CS1 (DSCP 8)", 0x20),
        "2": ("CS2 (DSCP 16)", 0x40),
        "3": ("CS3 (DSCP 24)", 0x60),
        "4": ("CS4 (DSCP 32)", 0x80),
        "5": ("CS5 (DSCP 40)", 0xA0),
        "6": ("CS6 (DSCP 48)", 0xC0),
        "7": ("CS7 (DSCP 56)", 0xE0),
        "8": ("AF11 (DSCP 10)", 0x28),
        "9": ("AF12 (DSCP 12)", 0x30),
        "10": ("AF13 (DSCP 14)", 0x38),
        "11": ("AF21 (DSCP 18)", 0x48),
        "12": ("AF22 (DSCP 20)", 0x50),
        "13": ("AF23 (DSCP 22)", 0x58),
        "14": ("AF31 (DSCP 26)", 0x68),
        "15": ("AF32 (DSCP 28)", 0x70),
        "16": ("AF33 (DSCP 30)", 0x78),
        "17": ("AF41 (DSCP 34)", 0x88),
        "18": ("AF42 (DSCP 36)", 0x90),
        "19": ("AF43 (DSCP 38)", 0x98),
        "20": ("EF (DSCP 46)", 0xB8)
    }

    parser = argparse.ArgumentParser(description='Network Tool CLI')
    args = parser.parse_args()

    while True:
        clear_screen()
        print("\nMenu:")
        print("1. Send ARP Request")
        print("2. Send Custom DSCP Ping")
        print("3. Exit")
        choice = input("Enter your choice (1-3): ")

        if choice == '1':
            target_ip = input("Enter target IP address for ARP request: ")
            count = int(input("Enter the number of ARP requests to send: "))
            send_arp_request(target_ip, count)
        elif choice == '2':
            print("\nSelect DSCP for ICMP Echo Request:")
            for key, value in dscp_options.items():
                print(f"{key}. {value[0]}")
            dscp_choice = input("Enter your choice for DSCP: ")
            if dscp_choice in dscp_options:
                target_ip = input("Enter target IP address for the ICMP Echo Request: ")
                dscp_hex = dscp_options[dscp_choice][1]
                send_dscp_ping(target_ip, dscp_hex)
            else:
                print("Invalid DSCP choice, please select a valid option.")
        elif choice == '3':
            print("Exiting program.")
            break
        else:
            print("Invalid choice, please choose 1, 2, or 3.")

if __name__ == '__main__':
    main()

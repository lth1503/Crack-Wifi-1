# Crack Wifi 

![Logo](assets/image.png)

### Scan và check pass wifi thông qua termux (Root).
    
- [Yêu cầu]
  - [Python](https://www.python.org)
  - [Pixiewps](https://www.kali.org/tools/pixiewps/)
  - [Wpa-supplicant](https://wiki.archlinux.org/title/wpa_supplicant)
 
### Cài đặt :

```bash
pkg update && pkg upgrade -y
pkg install root-repo -y
pkg install git tsu python wpa-supplicant pixiewps iw openssl -y
git clone https://github.com/lth1503/Crack-Wifi-1
cd Crack-Wifi-1
chmod +x main.py
```
# Nhập thủ công và lưu ý:
(Termux hỏi Y/N, chọn Y)

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
git clone https://github.com/lth1503/Crack-Wifi-1
```
```bash
cd Crack-Wifi-1
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
cd Crack-Wifi-1
```

```bash
sudo python main.py -i wlan0 -K
```

#### Ghi chú :
• Tắt mạng, tắt điểm truy cập, bật vị trí

• Màu xanh là tỉ lệ 60-80% thành công với router đã căn chỉnh wps

• Màu đỏ là ~10%

• Màu trắng là <50%

• Màu vàng là 50%


## Ảnh chụp màn hình

| Banner | Cracked | Saved Data | config.txt | 
| :---: | :---: | :---: | :---: |
| ![image](https://raw.githubusercontent.com/anbuinfosec/anbuinfosec/refs/heads/main/assets/wipwn/1.jpg) | ![image](https://raw.githubusercontent.com/anbuinfosec/anbuinfosec/refs/heads/main/assets/wipwn/2.jpg) | ![image](https://raw.githubusercontent.com/anbuinfosec/anbuinfosec/refs/heads/main/assets/wipwn/3.jpg) | ![image](https://raw.githubusercontent.com/anbuinfosec/anbuinfosec/refs/heads/main/assets/wipwn/4.jpg) |


### ❤️ Cảm ơn vì 🌟 và forks
[![Stargazers repo danh sách cho @anbuinfosec/wipwn](https://reporoster.com/stars/dark/anbuinfosec/wipwn)](https://github.com/anbuinfosec/wipwn/stargazers)
[![Forkers repo roster for @anbuinfosec/wipwn](https://reporoster.com/forks/dark/anbuinfosec/wipwn)](https://github.com/anbuinfosec/wipwn/network/members)

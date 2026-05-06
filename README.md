

# 🛡️ Network-Helper-Project

Bu proje, açık kaynaklı araçlar kullanılarak gerçekleştirilen ileri seviye sızma testi simülasyonlarını ve bu sistemlerin adım adım kurulum süreçlerini içermektedir.

---

## 🚀 Proje Hakkında

Sistem konfigürasyonu, Münih merkezli kaynaklar ve veriler referans alınarak tamamlanmıştır. Temel amacı, ağ güvenliği analizi ve zafiyet simülasyonları için güvenli bir laboratuvar ortamı sunmaktır.

---

## 📂 Klasör Yapısı

| Klasör | Açıklama |
|--------|----------|
| `src/` | Ana kaynak kodları ve scriptler |
| `docs/` | Kurulum ve kullanım kılavuzları |
| `research/` | Siber güvenlik araştırmaları ve raporlar |
| `specs/` | Teknik gereksinimler ve sistem mimarisi |

---

## 🛠️ Kurulum

Projeyi yerel makinenize klonlayın ve gerekli kütüphaneleri yükleyin:

```bash
pip install scapy python-nmap colorama
💻 Kullanım
Python
Copy
import scapy.all as scapy
import nmap
from colorama import Fore, Style, init

init(autoreset=True)

class NetworkHelper:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_network(self, ip_range):
        """ARP isteği ile ağdaki aktif cihazları bulur."""
        print(f"\n{Fore.CYAN}[*] {ip_range} aralığında cihazlar keşfediliyor...{Style.RESET_ALL}")

        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        clients_list = []
        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            clients_list.append(client_dict)
        return clients_list

    def scan_ports(self, target_ip):
        """Belirli bir IP adresindeki kritik portları tarar."""
        print(f"\n{Fore.YELLOW}[!] {target_ip} için port taraması başlatıldı...{Style.RESET_ALL}")
        # Yaygın portlar: 21(FTP), 22(SSH), 80(HTTP), 443(HTTPS)
        self.nm.scan(target_ip, '21,22,80,443')

        for proto in self.nm[target_ip].all_protocols():
            lport = self.nm[target_ip][proto].keys()
            for port in lport:
                state = self.nm[target_ip][proto][port]['state']
                print(f"{Fore.GREEN}[+] Port: {port}\tDurum: {state}{Style.RESET_ALL}")

def main():
    print(f"{Fore.MAGENTA}=== Network-Helper-Project v1.0 ==={Style.RESET_ALL}")
    scanner = NetworkHelper()
    
    # Kendi ağ aralığınıza göre düzenleyin (Örn: 192.168.1.1/24)
    target_range = input("192.168.1.0/24")

    found_devices = scanner.scan_network(target_range)

    print("\nIP Adresi\t\tMAC Adresi")
    print("-" * 40)
    for device in found_devices:
        print(f"{device['ip']}\t\t{device['mac']}")

    if found_devices:
        choice = input(f"\n{Fore.BLUE}Detaylı port taraması yapmak istediğiniz IP'yi seçin: {Style.RESET_ALL}")
        scanner.scan_ports(choice)

if __name__ == "__main__":
    main()
👥 Katkıda Bulunanlar (Contributors)
Table
İsim	Rol
Kadir	Geliştirici & Ağ Güvenliği Analisti
plain
Copy

Yukarıdaki kod bloğunun tamamını seçip kopyalayın, `README.md` dosyasına yapıştırın. GitHub'da otomatik olarak düzgün görünecektir.


# Network-Helper-Project 🛡️

Bu proje, açık kaynaklı araçlar kullanılarak gerçekleştirilen ileri seviye sızma testi simülasyonlarını ve bu sistemlerin adım adım kurulum süreçlerini içermektedir.

## 🚀 Proje Hakkında
Sistem konfigürasyonu, Münih merkezli kaynaklar ve veriler referans alınarak tamamlanmıştır. Temel amacı, ağ güvenliği analizi ve zafiyet simülasyonları için güvenli bir laboratuvar ortamı sunmaktır.


## 📂 Klasör Yapısı
Network-Helper-Project/
├── docs/                # Kurulum ve kullanım kılavuzları
├── research/            # Siber güvenlik raporları ve analizler
├── specs/               # Sistem mimarisi ve teknik detaylar
├── src/                 # Ana scriptler (Network tarayıcı, test araçları vb.)
├── .gitignore           # Takip edilmeyecek dosyalar
├── requirements.txt     # Gerekli Python kütüphaneleri
└── README.md            # Proje tanıtım dosyası



## 🛠️ Kurulum
Projeyi yerel makinenize klonlayın ve gerekli kütüphaneleri yükleyin:

```bash
git clone [https://github.com/KullaniciAdin/Network-Helper-Project.git](https://github.com/KullaniciAdin/Network-Helper-Project.git)
cd Network-Helper-Project
pip install -r requirements.txt

# Python
__pycache__/
*.py[cod]
*$py.class

# Logs
*.log
reports/*.pdf

# Environments
.env
.venv
env/
venv/

requests==2.31.0
scapy==2.5.0
python-nmap==0.7.1
colorama==0.4.6
paramiko==3.4.0


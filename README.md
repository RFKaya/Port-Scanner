<div align="center">
  <img src="https://www.istinye.edu.tr/sites/default/files/2025-07/isu_logo_tr-1.svg" width="220" alt="İstinye Üniversitesi Logo" />
  <br />
  <h3>🏙️ İSTİNYE ÜNİVERSİTESİ</h3>
  <h1>🛡️ SECOPS PORT SCANNER</h1>
  <p><i>Yüksek Performanslı, Asenkron Ağ Güvenliği ve Zafiyet Analiz Aracı</i></p>

  <img src="https://img.shields.io/badge/Versiyon-1.6.0-blue?style=for-the-badge&logo=github" />
  <img src="https://img.shields.io/badge/Rust-1.75%2B-orange?style=for-the-badge&logo=rust" />
  <img src="https://img.shields.io/badge/Lisans-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=for-the-badge" />
  <br>
  <img src="https://img.shields.io/badge/Durum-Aktif-brightgreen?style=flat-square" />
  <img src="https://img.shields.io/badge/Kapsam-Vize_Projesi-blueviolet?style=flat-square" />
  <img src="https://img.shields.io/badge/Dokümantasyon-%E2%9C%85-success?style=flat-square" />
  <img src="https://img.shields.io/badge/Güvenlik-WAF_Atlatma-red?style=flat-square" />
</div>

---

## 📖 Proje Hakkında

**SecOps Port Scanner**, üniversite vize projesi kapsamında geliştirilmiş, modern ağ güvenlik ihtiyaçlarını karşılamayı amaçlayan hibrit bir port tarama aracıdır. Rust programlama dilinin sunduğu bellek güvenliği ve yüksek performans avantajlarını kullanarak, binlerce portu saniyeler içinde tarayabilmektedir. Proje, hem profesyonel siber güvenlik uzmanları için güçlü bir **CLI (Komut Satırı)** arayüzü, hem de son kullanıcılar için görsel açıdan zengin bir **Web Kontrol Paneli** sunar.

Bu araç, sadece portların açık olup olmadığını kontrol etmekle kalmaz, aynı zamanda tespit edilen servisleri bir zafiyet veritabanıyla eşleştirerek olası güvenlik risklerini raporlar.

---

## 👨‍🏫 Akademik Bilgiler

- **Üniversite:** İstinye Üniversitesi
- **Geliştirici:** Rauf Fatih Kaya
- **Danışman:** Keyvan Arasteh Abbasabad
- **Ders:** Sızma Testi (Vize Projesi)

---

## 🗂️ İçindekiler

1.  [Özellikler](#-özellikler)
2.  [Hızlı Başlangıç](#-hızlı-başlangıç)
3.  [Kullanım Senaryoları](#-kullanım-senaryoları)
4.  [Teknik Mimari](#-teknik-mimari)
5.  [Dokümantasyon Dizinleri](#-dokümantasyon-dizinleri)
6.  [Lisans](#-lisans)

---

## ✨ Özellikler

- ⚡ **Asenkron Motor:** `Tokio` runtime sayesinde ağ IO işlemlerinde maksimum verimlilik.
- 🥷 **Gizli Tarama (SYN Scan):** Hedef sistemlerde iz bırakmadan (3-way handshake tamamlamadan) tarama yapabilme yeteneği.
- 🌐 **Modern Web Paneli:** `Axum` ve `Chart.js` ile desteklenen, canlı veri takibi yapılabilen dashboard.
- 🛡️ **Zafiyet Eşleştirme:** Açık portlardaki servisleri bilinen CVE verileriyle analiz etme.
- 📊 **Veri Saklama:** Tüm tarama sonuçlarının JSON formatında otomatik olarak kaydedilmesi ve geçmişin web panelinden izlenmesi.
- 🚀 **Özelleştirilebilir Hız:** `Concurrency` ayarı ile sistem kaynaklarına göre tarama hızını dinamik olarak belirleme.

---

## 🚀 Hızlı Başlangıç

### 1. Kurulum
Projenin çalışması için sisteminizde Rust ve paket yakalama kütüphanelerinin (Npcap/libpcap) yüklü olması gerekir.

```bash
# Bağımlılıkları yükleyin ve projeyi derleyin
cargo build --release
```

### 2. Web Panelini Başlatma (Önerilen)
Web üzerinden görsel bir deneyim için:
```bash
cargo run -- web
```
Ardından [http://localhost:3000](http://localhost:3000) adresini ziyaret edin.

### 3. CLI Üzerinden Tarama
Daha hızlı ve doğrudan sonuçlar için:
```bash
cargo run -- pentest port-scan 127.0.0.1 --range 1-1000 --syn
```

### 🐳 4. Docker ile Çalıştırma
Uygulamayı herhangi bir bağımlılık (Npcap vb.) yüklemeden Docker üzerinde çalıştırabilirsiniz:

```bash
# Sadece Docker imajını oluşturun
docker build -t secops-scanner .

# Docker Compose ile tüm ortamı başlatın
docker-compose up -d
```

> [!CAUTION]
> Docker üzerinden **SYN Tarama** yapabilmek için kapsayıcıya ağ yetkileri verilmelidir. `docker-compose.yml` dosyasında bu yetkiler (`cap_add: [NET_ADMIN, NET_RAW]`) tanımlanmıştır.

---

## 🎬 Demo

Projenin temel özelliklerini, CLI kullanımını ve Web Paneli üzerinden canlı tarama sürecini aşağıdaki demodan izleyebilirsiniz:

### Web Panel Tanıtımı
![SecOps Scanner Demo](./demo/project-demo.webp)

### Örnek CLI Çıktısı (Zafiyet Analizi)
Aşağıda, yerel bir hedef üzerinde yapılan örnek bir taramanın terminal çıktısı yer almaktadır:

```bash
# Yerel hedef üzerinde 20-30 port aralığında tarama
cargo run -- pentest port-scan 127.0.0.1 -r 20-100
```

**Sonuçlar (Özet):**
| Port | Protokol | Servis | Güvenlik Durumu |
|------|----------|--------|-----------------|
| 21 | TCP | FTP | 🟡 MEDIUM (Cleartext) |
| 23 | TCP | Telnet | 🔴 CRITICAL (No Encryption) |
| 80 | TCP | HTTP | 🔵 LOW (Unencrypted) |

### Proof-of-Concept (Bağlantı Testi)
Scanner tarafından açık olarak tespit edilen portlara erişim doğrulaması (PoC):
```powershell
# Port 23 (Telnet) bağlantı testi
Test-NetConnection -ComputerName 127.0.0.1 -Port 23

# Çıktı:
# ComputerName     : 127.0.0.1
# RemotePort       : 23
# TcpTestSucceeded : True
```

---

## 🛠️ Kullanım Senaryoları

### Senaryo A: Yerel Ağ Güvenlik Testi
Kendi ağınızdaki cihazların hangi servisleri dışarı açtığını görmek için standart bir TCP taraması yapabilirsiniz. Bu, yanlışlıkla açık bırakılan portları (örn: 3389 RDP, 22 SSH) tespit etmenizi sağlar.

### Senaryo B: Gizli Pentest Çalışması
Hedef sistemin güvenlik duvarı kurallarını veya log sistemlerini tetiklemeden tarama yapmak istiyorsanız `--syn` bayrağını kullanarak paket seviyesinde tarama gerçekleştirebilirsiniz.

### Senaryo C: Geniş Kapsamlı Tarama
Tüm port aralığını (1-65535) hızlıca taramak için `concurrency` değerini artırarak (örn: `-c 2000`) süreci dakikalar bazına indirebilirsiniz.

---

## 🏗️ Teknik Mimari

Proje, modüler bir yapı üzerine inşa edilmiştir:
- **Scanner Core:** TCP, UDP ve SYN protokollerini temsil eden asenkron fonksiyonlar.
- **Persistence Layer:** Tarama sonuçlarını dosya sistemine asenkron olarak yazan katman.
- **Web Engine:** RESTful API ve statik dosya sunumu yapan Axum sunucusu.
- **Frontend Assets:** Vanilla JS ve modern CSS ile tasarlanmış, veri odaklı arayüz.

Detaylı teknik bilgi için [MİMARİ KILAVUZUNA](docs/ARCHITECTURE.md) göz atın.

---

## 📂 Dokümantasyon Dizinleri

Projenin tüm detaylarını aşağıdaki belgelerde bulabilirsiniz:

- 🛠️ [**Kurulum Kılavuzu (INSTALLATION)**](docs/INSTALLATION.md): Windows ve Linux için detaylı kurulum adımları.
- 📖 [**Kullanım Kılavuzu (USAGE)**](docs/USAGE.md): CLI komutları ve Web arayüzü kullanım detayları.
- 🏛️ [**Mimari Dokümantasyon (ARCHITECTURE)**](docs/ARCHITECTURE.md): Projenin teknik yapısı ve çalışma mantığı.
- 🛡️ [**Güvenlik ve Etik (SECURITY)**](docs/SECURITY.md): Etik kullanım ilkeleri ve yasal uyarılar.

---

## 🛠️ Proje Geliştirme Süreci ve Zorluklar

Bu projenin geliştirilmesi sırasında karşılaşılan en büyük teknik zorluk, binlerce portun asenkron olarak taranırken sistem kaynaklarının (file descriptors) tükenmemesini sağlamaktı. `Tokio` kanalları ve sınırlı `concurrency` yapıları kullanılarak bu sorun çözülmüştür.

- **SYN Scan Entegrasyonu:** Raw socket kullanımı için işletim sistemi katmanındaki farklılıklar (Windows Npcap vs Linux libpcap) `pnet` kütüphanesi ve platforma özgü ağ ayarlarıyla yönetilmiştir.
- **Web-CLI Senkronizasyonu:** CLI üzerinden yapılan taramaların web panelinde anında görünebilmesi için merkezi bir JSON tabanlı `persistence` (kalıcılık) katmanı tasarlanmıştır.

---

## 🔮 Gelecek Çalışmalar ve Yol Haritası

Projenin bir sonraki aşamasında aşağıdaki özelliklerin eklenmesi planlanmaktadır:
- 🐳 **Docker Desteği:** Tek komutla tüm ortamın (Rust + Web + Npcap) ayağa kaldırılması.
- 📡 **Servis Banner Grabbing:** Açık portlardaki servislerden sürüm bilgilerini (banner) çekerek daha hassas zafiyet analizi.
- 📱 **Mobil Uyumlu Arayüz:** Web panelinin mobil cihazlarda daha verimli çalışması için responsive iyileştirmeler.
- 📧 **Anlık Bildirimler:** Kritik bir port veya zafiyet tespit edildiğinde Telegram veya Mail üzerinden uyarı gönderimi.

---

## 📜 Lisans

Bu proje **MIT Lisansı** ile korunmaktadır. Eğitim amaçlı kullanımlarda kaynak gösterilmesi rica olunur.

---

<div align="center">
  <p>Geliştirici: <b>Rauf Fatih Kaya</b> tarafından İstinye Üniversitesi vize ödevi olarak hazırlanmıştır.</p>
  <p><i>© 2026 SecOps Port Scanner - Tüm Hakları Saklıdır.</i></p>
</div>

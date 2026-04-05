<div align="center">
  <img src="https://img.shields.io/badge/VERSION-1.5.1-blue?style=for-the-badge&logo=github" />
  <img src="https://img.shields.io/badge/RUST-1.75%2B-orange?style=for-the-badge&logo=rust" />
  <img src="https://img.shields.io/badge/LICENSE-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/PLATFORM-WINDOWS%20%7C%20LINUX-lightgrey?style=for-the-badge" />
  <br>
  <img src="https://img.shields.io/badge/MAINTENANCE-ACTIVE-brightgreen?style=flat-square" />
  <img src="https://img.shields.io/badge/PRs-WELCOME-blueviolet?style=flat-square" />
  <img src="https://img.shields.io/badge/SECURE-WAF_EVASION-red?style=flat-square" />
  <img src="https://img.shields.io/badge/INTERFACE-WEB_%7C_CLI-blue?style=flat-square" />

  # 🛡️ SECOPS PORT SCANNER

  **Hedef sistemlerdeki açık portları saniyelik hızlarla tespit eden; TCP/UDP desteği, dahili zafiyet veritabanı ve asenkron mimarisiyle hem Web hem de CLI üzerinden çalışan modern bir ağ güvenlik aracıdır.**
</div>

---

## 🛠️ Kurulum ve Hazırlık

Projenin tak-çalıştır (Plug & Play) mantığında olması için gerekli tüm bağımlılıklar ayarlanmıştır:

- **Rust**: [rustup.rs](https://rustup.rs) adresinden yüklü olmalıdır.
- **Windows Kullanıyorsanız:** TCP SYN taraması için gerekli olan `Packet.lib` dosyası proje kök dizinine dahil edilmiştir. `build.rs` sayesinde ek bir ortam değişkeni ayarlamanıza gerek kalmadan `cargo build` komutuyla derleyebilirsiniz. (Not: Taramaların çalışması için sistemde Npcap/WinPcap sürücüsünün yüklü olması yeterlidir.)
- **Linux Kullanıyorsanız:** Paket yakalama işlemleri (SYN scan) için **yönetici izinleri (`sudo`)** gereklidir.

### Derleme
```bash
cargo build --release
```

---

## 🌐 Web Arayüzü (Önerilen)
Gelişmiş bir web paneli üzerinden canlı tarama, grafiksel istatistikler ve zafiyet eşleştirmesi yapmak için:

**Çalıştırma Komutu:**
```bash
cargo run -- web
```
**Adres:** [http://localhost:3000](http://localhost:3000)

### Öne Çıkan Özellikler:
- 📊 **Canlı Port Durum Grafikleri** (Chart.js)
- 🛡️ **Zafiyet Eşleştirme** (Vulnerability Mapping)
- 📝 **Kaydedilen Tarama Geçmişi** (History)
- 📥 **CSV Formatında Dışa Aktarma**
- 🔍 **Anlık Arama ve Duruma Göre Filtreleme**

---

## 💻 Komut Satırı Kullanımı (CLI)

### Standart Tarama (TCP Connect)
```bash
cargo run -- pentest port-scan <hedef> --range 1-1000
```

### Stealth Tarama (SYN - Admin/Root Gerektirir)
```bash
cargo run -- pentest port-scan <hedef> --syn
```

### UDP Tarama
```bash
cargo run -- pentest port-scan <hedef> --udp
```

### Yüksek Hızlı Eşzamanlı Tarama (Concurrency)
```bash
cargo run -- pentest port-scan <hedef> -c 1000
```

---

## ⚙️ Parametreler

| Parametre | Kısa Ad | Açıklama | Varsayılan |
| :--- | :---: | :--- | :--- |
| `--range` | `-r` | Port aralığı (Örn: 1-65535, 80,443) | `1-1024` |
| `--timeout` | `-t` | Port başına zaman aşımı (ms) | `1000` |
| `--concurrency`| `-c` | Aynı anda taranacak port sayısı | `500` |
| `--format` | `-f` | CLI çıktı formatı (`md`, `json`) | `md` |
| `--syn` | | TCP SYN (Stealth) tarama modu | - |
| `--udp` | | UDP protokol tarama modu | - |

---

## 📜 Lisans
Bu proje **MIT Lisansı** altında lisanslanmıştır. Daha fazla bilgi için [LICENSE](LICENSE) dosyasına göz atın.

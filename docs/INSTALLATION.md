# 🛠️ Kurulum Kılavuzu

Bu belge, **SecOps Port Scanner** projesini farklı işletim sistemlerinde nasıl kuracağınızı ve çalıştıracağınızı detaylandırmaktadır.

## 📋 Gereksinimler

Projenin derlenmesi ve çalışması için aşağıdaki araçların sisteminizde yüklü olması gerekir:

1.  **Rust Toolchain**: En az v1.75 veya üzeri bir sürüm önerilir.
    - [rustup.rs](https://rustup.rs) adresinden yükleyebilirsiniz.
2.  **Paket Yakalama Kütüphaneleri**:
    - **Windows**: [Npcap](https://npcap.com/) veya **WinPcap**. (Npcap yüklenirken "Install Npcap in WinPcap API-compatible Mode" seçeneğinin işaretli olduğundan emin olun).
    - **Linux**: `libpcap-dev` paketi.

---

## 💻 İşletim Sistemi Spesifik Ayarlar

### Windows

Windows üzerinde özellikle **SYN Scan** (Stealth Scan) yapabilmek için `Npcap` sürücüsüne ihtiyaç duyulur.

1.  **Npcap Yükleme**: [npcap.com](https://npcap.com/) adresinden en güncel sürümü indirin.
2.  **Kurulum**: Yükleme sırasında WinPcap uyumluluk modunu aktif edin.
3.  **Derleme**: Standart PowerShell veya CMD kullanarak derleme yapabilirsiniz.

### Linux (Ubuntu/Debian)

Linux'ta raw socket kullanımı için genellikle root yetkileri gereklidir.

1.  **Bağımlılıkları Yükleyin**:
    ```bash
    sudo apt update
    sudo apt install build-essential libpcap-dev
    ```
2.  **İzinler**:
    SYN taraması yaparken `sudo` kullanmanız gerekebilir:
    ```bash
    sudo cargo run -- pentest port-scan <hedef> --syn
    ```
    Veya binary dosyasına `cap_net_raw` yetkisi verebilirsiniz.

---

## 🚀 Projeyi Derleme

Depoyu klonladıktan sonra (veya yerel dizindeyseniz) aşağıdaki komutu çalıştırarak projeyi optimize edilmiş (release) modda derleyebilirsiniz:

```bash
cargo build --release
```

Derlenen dosya `target/release/port_scanner` (Windows'ta `.exe`) dizininde oluşacaktır.

---

## 🔍 Sorun Giderme

- **"Npcap not found" Hatası**: Windows'ta Npcap yüklü olsa bile yol tanımlanmamış olabilir. Yeniden başlatmayı veya Npcap'i "WinPcap compatibility mode" ile tekrar kurmayı deneyin.
- **"Permission Denied" (Linux)**: Raw socket oluşturulamıyor demektir. Komutu `sudo` ile çalıştırmayı deneyin.
- **Yavaş Tarama**: Güvenlik duvarınız (Firewall) veya antivirüs yazılımınız yüksek hızlı taramaları engelliyor olabilir.

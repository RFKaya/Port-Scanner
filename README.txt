SECOPS PORT SCANNER
===================

KURULUM
----------
- Rust yüklü olmalıdır (https://rustup.rs).
- Windows: Npcap veya WinPcap gereklidir (SYN scan için).
- Linux: Paket yakalama izinleri (sudo) gereklidir.

Komut: cargo build --release





WEB ARAYÜZÜ (ÖNERİLEN)
-------------------------
Modern bir arayüzle localhost üzerinden tarama yapmak için:

Komut: cargo run -- web
Adres: http://localhost:3000

KOMUT SATIRI KULLANIMI
-------------------------
Standart Tarama (TCP Connect):
> cargo run -- pentest port-scan <hedef> --range 1-1000

Stealth Tarama (SYN - Admin gerektirir):
> cargo run -- pentest port-scan <hedef> --syn

UDP Tarama:
> cargo run -- pentest port-scan <hedef> --udp

JSON Çıktısı:
> cargo run -- pentest port-scan <hedef> --format json

--range    : Port aralığı (Örn: 1-65535, 80) [Varsayılan: 1-1024]
--timeout  : Port başına zaman aşımı (ms) [Varsayılan: 1000]
--format   : Çıktı formatı (md, json) [Varsayılan: md]
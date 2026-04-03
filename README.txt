SECOPS PORT SCANNER
==========================

Yüksek performanslı, asenkron ve modern bir ağ güvenlik tarayıcısı.

KURULUM
----------
- Rust yüklü olmalıdır (https://rustup.rs).
- Windows: Npcap veya WinPcap gereklidir (TCP SYN scan için).
- Linux: Paket yakalama izinleri (sudo) gereklidir.

Derleme: cargo build --release

WEB ARAYÜZÜ (ÖNERİLEN)
-------------------------
Gelişmiş bir web paneli üzerinden canlı tarama, grafiksel istatistikler ve 
zafiyet eşleştirmesi yapmak için:

Komut: cargo run -- web
Adres: http://localhost:3000

Özellikler:
- Canlı Port Durum Grafikleri (Chart.js)
- Zafiyet Eşleştirme (Vulnerability Mapping)
- Kaydedilen Tarama Geçmişi (History)
- CSV Formatında Dışa Aktarma
- Anlık Arama ve Duruma Göre Filtreleme

KOMUT SATIRI KULLANIMI (CLI)
-----------------------------
Standart Tarama (TCP Connect):
> cargo run -- pentest port-scan <hedef> --range 1-1000

Stealth Tarama (SYN - Admin gerektirir):
> cargo run -- pentest port-scan <hedef> --syn

UDP Tarama:
> cargo run -- pentest port-scan <hedef> --udp

Yüksek Hızlı Eşzamanlı Tarama (Concurrency):
> cargo run -- pentest port-scan <hedef> -c 1000

PARAMETRELER
-------------
--range       (-r) : Port aralığı (Örn: 1-65535, 80,443) [Varsayılan: 1-1024]
--timeout     (-t) : Port başına zaman aşımı (ms) [Varsayılan: 1000]
--concurrency (-c) : Aynı anda taranacak port sayısı [Varsayılan: 500]
--format      (-f) : CLI çıktı formatı (md, json) [Varsayılan: md]
--syn              : TCP SYN (Stealth) tarama modu
--udp              : UDP protokol tarama modu
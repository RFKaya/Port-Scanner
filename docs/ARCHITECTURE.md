# 🏛️ Mimari Tasarım ve Teknik Detaylar

SecOps Port Scanner, yüksek performanslı bir ağ tarayıcısıdır. Projenin kalbinde Rust dilinin asenkron gücü ve Tokio kütüphanesi yer almaktadır.

---

## 🛠️ Temel Teknolojiler

Bu projenin temel yapı taşları ve bileşenleri:

1.  **Dil**: Rust
    - Bellek güvenliği (Memory Safety)
    - Veri yarışı (Data Race) engelleme
2.  **Asenkron Runtime**: `Tokio`
    - Binlerce ağ isteğini aynı anda yönetmek için kullanılır.
3.  **Web Sunucusu**: `Axum`
    - Tip güvenli (Type-safe) ve hızlı bir web servis katmanı.
4.  **CLI Ayırıcı (CLI Parser)**: `Clap`
    - Komut satırı argümanlarını kolayca yönetmeyi sağlar.
5.  **Ağ Kütüphaneleri**:
    - `pnet`: Raw socket (SYN/TCP) paket başlıklarını manuel olarak oluşturmak için kullanılır.

---

## 🏗️ Proje Yapısı

Proje dizinleri şu şekilde organize edilmiştir:

```text
src/
├── main.rs         # Program giriş noktası ve CLI argüman yönetimi
├── web.rs          # Web sunucusu, API rotaları ve WebSocket yönetimi
├── scanner/        # Tarama motoru ve protokol mantığı (TCP, SYN, UDP)
├── modules/        # Zafiyet haritalama ve veritabanı eşleştirme
└── persistence/    # JSON tabanlı tarama geçmişini kaydetme ve okuma
```

---

## ⚙️ Tarama Motoru Nasıl Çalışır?

### 1. TCP Connect Scan
Bu en basit tarama türüdür. Hedef port ile tam bir 3'lü el sıkışma (3-way handshake) gerçekleştirilir.
- **İşlem**: `SYN -> SYN-ACK -> ACK`
- **Tamamlanma**: Bağlantı başarıyla kurulursa port `Open` (Açık) olarak işaretlenir ve hemen kapatılır.

### 2. TCP SYN Scan (Stealth)
Hedef port ile tam bir bağlantı kurmaz, sadece bir `SYN` paketi gönderir.
- **İşlem**: `SYN -> SYN-ACK (Port Açık)` veya `SYN -> RST (Port Kapalı)`.
- **Avantaj**: Bağlantı tam kurulmadığı için hedef sistemin uygulama loglarında görünmez.

### 3. Zafiyet Eşleştirme (Vulnerability Mapping)
Açık bulunan portlardaki servis isimleri (`http`, `ssh`, `mysql` vb.) yerel bir veritabanı ile eşleştirilir.
- **Veritabanı**: Dahili güvenlik modülü, bilinen yaygın açıkların ve risklerin bir listesini tutar.
- **Süreç**: Port taraması bittikten sonra sonuçlar bu modülden geçer ve risk skoru hesaplanır.

---

## ⚡ Performans Optimizasyonu

Proje, hızı artırmak için **Eşzamanlılık (Concurrency)** kullanır. Binlerce portu tararken program her portun cevabını beklemez; bunun yerine tüm istekleri asenkron olarak gönderir ve gelen cevapları eşzamanlı olarak dinler. Bu işlem CPU kullanımını düşük tutarken ağ bant genişliğini en üst düzeye çıkarır.

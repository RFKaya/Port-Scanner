## Vize — Rauf Fatih Kaya 

### Modül: Modül 1 - Port Scanner
### Zorluk: ⭐⭐

### Açıklama
Hedef sistemlerdeki açık portları tespit ederek güvenlik zafiyetlerini raporlayan bir ağ tarama aracıdır. Rust dilinin performansı ve asenkron (Tokio) mimarisi sayesinde binlerce portu saniyeler içinde tarayabilir; elde ettiği verileri hem profesyonel bir CLI hem de modern bir web paneli üzerinden anlık olarak görselleştirir.

### Kullanım
```bash
# Standart TCP taraması için:
cargo run -- pentest port-scan 127.0.0.1 --range 1-1024

# Web panelini başlatmak için:
cargo run -- web
```

### Test
```bash
cargo test
```

### Öğrendiklerim
*   **Asenkron Programlama:** `Tokio` ile binlerce ağ isteğini eşzamanlı yönetmeyi ve yüksek performanslı asenkron mimariyi öğrendim.
*   **Ağ Protokolleri:** TCP Connect, SYN ve UDP yöntemleriyle ağ seviyesinde paket analizini ve raw socket kullanımını kavradım.
*   **Web Entegrasyonu:** `Axum` ile backend mimarisi kurmayı ve verileri web paneli üzerinden görselleştirmeyi deneyimledim.
*   **Güvenli Yazılım:** Rust'ın sahiplik (ownership) ve hata yönetimi mekanizmalarıyla dayanıklı sistemler geliştirmeyi öğrendim.

# 🛡️ Güvenlik ve Etik Kullanım Yönergeleri

**SecOps Port Scanner**, güvenlik uzmanları, sistem yöneticileri ve öğrenciler için bir eğitim/test aracı olarak geliştirilmiştir. Bu aracın kullanımıyla ilgili önemli kurallar ve uyarılar aşağıdadır.

---

## 🚫 Yasal Uyarı

Bu aracı sadece **sahibi olduğunuz** veya **açıkça yazılı izin aldığınız** sistemler üzerinde kullanın. Yetkisiz ağ taraması yapmak birçok ülkede yerel yasaları ihlal edebilir ve siber suç kapsamında değerlendirilebilir. 

**Geliştirici**, bu aracın kötüye kullanımından veya neden olabileceği herhangi bir zarardan sorumlu tutulamaz.

---

## ⚖️ Etik Hackerlık (Ethical Hacking)

1.  **İzin Alın**: Bir ağı taramadan önce mutlaka yetkili kişilerden onay alın.
2.  **Zarar Vermeyin**: Taramaların hedef sistemin performansını düşürmediğinden (DoS/Denial of Service) emin olun.
3.  **Gizliliği Koruyun**: Tarama sonuçlarını ve bulguları yetkisiz 3. şahıslarla paylaşmayın.
4.  **Raporlayın**: Bulunan açıkları sistem sahibine sorumlu bir şekilde (Responsible Disclosure) bildirin.

---

## 🛠️ Güvenli Kullanım İpuçları

- **Aşırı Hızdan Kaçının**: Çok yüksek `concurrency (-c)` ayarları ağda tıkanmalara veya IDS/IPS sistemleri tarafından engellenmenize neden olabilir.
- **Güvenli Ortam**: Denemelerinizi `localhost` veya `Docker` gibi izole ortamlarda yaparak başlayın.
- **Güncel Veritabanı**: Zafiyet eşleştirmelerinin doğruluğu için modülleri ve veritabanlarını güncel tutun.

---

## 📋 Güvenlik Önlemleri Hakkında

Bu proje, açık kaynak topluluğuna katkı sağlama ve siber güvenlik bilincini artırma amacıyla tasarlanmıştır. Güçlü bir araç, büyük sorumluluk getirir. Lütfen bu aracı sadece etik amaçlarla kullanın.

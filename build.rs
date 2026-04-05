fn main() {
    // Windows üzerinde Npcap/WinPcap için gerekli olan Packet.lib dosyasının
    // proje dizininden (root) otomatik bulunmasını sağlar.
    #[cfg(windows)]
    println!("cargo:rustc-link-search=native=.");
}

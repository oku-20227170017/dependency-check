import os
import subprocess
import argparse
import json
import tempfile

# Renk kodları
RENK_YESIL = '\033[92m'
RENK_MAVI = '\033[94m'
RENK_SARI = '\033[93m'
RENK_KIRMIZI = '\033[91m'
RENK_CIYAN = '\033[96m'
RENK_BOLD = '\033[1m'
RENK_RESET = '\033[0m'

def parse_and_display_js_report(json_path, project_name):
    """
    Oluşturulan JSON raporunu (HEM MAVEN HEM DE JAVASCRIPT İÇİN) okur ve CLI'a basar.
    Not: Fonksiyon adı 'js' olarak kalsa da, her iki tip rapor için de çalışır.
    """
    print(f"\n{RENK_BOLD}{RENK_MAVI}---------- TARAMA SONUÇLARI: {project_name} ----------{RENK_RESET}")
    try:
        with open(json_path, 'r', encoding='utf-8') as f: data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"{RENK_KIRMIZI}HATA: Rapor dosyası okunamadı veya bozuk: {e}{RENK_RESET}"); return
    
    dependencies = data.get('dependencies', [])
    vulnerable_deps = [d for d in dependencies if d.get('vulnerabilities')]
    
    if not vulnerable_deps:
        print(f"\n{RENK_YESIL}✔ Tebrikler! Hiçbir zafiyet bulunamadı.{RENK_RESET}")
        print(f"{RENK_MAVI}----------------------------------------------------{RENK_RESET}\n")
        return

    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    total_vulnerabilities = 0
    for dep in vulnerable_deps:
        for vuln in dep.get('vulnerabilities', []):
            total_vulnerabilities += 1
            severity = vuln.get('severity', 'UNKNOWN').upper()
            if severity in severity_counts:
                severity_counts[severity] += 1

    print(f"\n{RENK_BOLD}ÖZET:{RENK_RESET}")
    print(f"  Taranan Bağımlılık Sayısı: {RENK_SARI}{len(dependencies)}{RENK_RESET}")
    print(f"  Zafiyet Bulunan Bağımlılık: {RENK_KIRMIZI}{len(vulnerable_deps)}{RENK_RESET}")
    print(f"  Toplam Zafiyet (CVE) Sayısı: {RENK_KIRMIZI}{total_vulnerabilities}{RENK_RESET}")
    print(f"\n{RENK_BOLD}Risk Dağılımı:{RENK_RESET}")
    print(f"  {RENK_KIRMIZI}CRITICAL: {severity_counts['CRITICAL']}{RENK_RESET}")
    print(f"  {RENK_SARI}HIGH    : {severity_counts['HIGH']}{RENK_RESET}")
    print(f"  {RENK_CIYAN}MEDIUM  : {severity_counts['MEDIUM']}{RENK_RESET}")
    print(f"  {RENK_YESIL}LOW     : {severity_counts['LOW']}{RENK_RESET}")

    print(f"\n{RENK_BOLD}ZAİYET DETAYLARI:{RENK_RESET}")
    for dep in vulnerable_deps:
        # Maven raporlarında 'filePath', JS raporlarında 'fileName' olabilir. İkisini de kontrol et.
        file_path = dep.get('filePath') or dep.get('packages', [{}])[0].get('id', 'Bilinmiyor')
        print(f"\nBağımlılık: {RENK_MAVI}{os.path.basename(file_path)}{RENK_RESET}")
        for vuln in dep.get('vulnerabilities', []):
            severity = vuln.get('severity', 'UNKNOWN').upper()
            cve_id = vuln.get('name', 'CVE-????-????')
            color = RENK_KIRMIZI if severity == 'CRITICAL' else RENK_SARI if severity == 'HIGH' else RENK_CIYAN if severity == 'MEDIUM' else RENK_YESIL
            print(f"  -> {color}{cve_id:<18}{RENK_RESET} Severity: {color}{severity}{RENK_RESET}")
    print(f"\n{RENK_MAVI}----------------------------------------------------{RENK_RESET}\n")

def run_command(command, cwd=None, show_log=False):
    """
    Belirtilen komutu çalıştırır ve çıkış kodunu döner.
    show_log=True ise, tüm çıktıyı ekrana basar.
    """
    print(f"  {RENK_SARI}Çalıştırılan Komut:{RENK_RESET} {' '.join(command)}")
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', cwd=cwd)
        if show_log: print(f"  {RENK_CIYAN}--- İŞLEM KAYDI BAŞLANGICI ---{RENK_RESET}")
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None: break
            if output and show_log: print(output.strip())
        return_code = process.poll()
        if show_log: print(f"  {RENK_CIYAN}--- İŞLEM KAYDI SONU (Çıkış Kodu: {return_code}) ---{RENK_RESET}")
        return return_code
    except FileNotFoundError:
        print(f"{RENK_KIRMIZI}HATA: '{command[0]}' komutu bulunamadı.{RENK_RESET}"); return -1
    except Exception as e:
        print(f"{RENK_KIRMIZI}❌ Beklenmedik bir hata oluştu: {e}{RENK_RESET}\n"); return -1

def find_and_scan_projects(root_directory):
    """
    Belirtilen dizinde pom.xml ve package.json dosyalarını bularak projeleri tarar.
    """
    print(f"\nTaranacak ana dizin: {root_directory}")
    print("pom.xml ve package.json dosyaları otomatik olarak aranacak...\n")
    found_projects = 0

    for dirpath, dirnames, filenames in os.walk(root_directory):
        dirnames[:] = [d for d in dirnames if d not in ['.git', 'target', 'node_modules']]
        project_name = os.path.basename(dirpath)

        # MAVEN TARAMASI (JSON ÇIKTISI ALACAK ŞEKİLDE GÜNCELLENDİ)
        if 'pom.xml' in filenames:
            found_projects += 1
            print(f"{RENK_MAVI}► Java/Maven projesi için tarama başlatılıyor: {project_name}{RENK_RESET}")
            
            # Maven komutuna `-Dformats=JSON` parametresi eklenerek JSON raporu oluşturması sağlanır.
            command = [
                'mvn', 
                '-B',  # Batch mode, daha temiz loglar için
                'org.owasp:dependency-check-maven:check', 
                '-Dformats=JSON' # Çıktı formatını JSON olarak ayarla
            ]
            
            # show_log=False ayarında bırakarak sadece kendi komut çıktımızı görüyoruz.
            return_code = run_command(command, cwd=dirpath, show_log=False)
            
            # Oluşturulan JSON raporunun yolu
            maven_report_path = os.path.join(dirpath, 'target', 'dependency-check-report.json')

            if return_code == 0 and os.path.exists(maven_report_path):
                print(f"{RENK_YESIL}✔ Maven taraması tamamlandı, sonuçlar işleniyor...{RENK_RESET}")
                # Maven tarafından oluşturulan JSON raporunu işlemek için mevcut fonksiyonu kullanıyoruz.
                parse_and_display_js_report(maven_report_path, project_name)
            elif return_code == 0:
                 print(f"{RENK_SARI}⚠️ Tarama komutu hatasız tamamlandı ancak 'target' klasöründe JSON rapor dosyası bulunamadı.{RENK_RESET}\n")
            else:
                print(f"{RENK_KIRMIZI}Maven taraması başarısız oldu (Hata Kodu: {return_code}).{RENK_RESET}\n")
            
            dirnames.clear() # Mevcut dizinin alt dizinlerine inmesini engelle
            continue

        # JAVASCRIPT TARAMASI (Değişiklik yok)
        if 'package.json' in filenames:
            with tempfile.TemporaryDirectory() as temp_dir:
                found_projects += 1
                print(f"{RENK_MAVI}► JavaScript projesi için tarama başlatılıyor: {project_name}{RENK_RESET}")
                
                command = ['dependency-check', '--project', project_name, '--scan', dirpath, '--format', 'JSON', '--out', temp_dir, '--disableJar', '--disableCentral']
                
                js_report_path = os.path.join(temp_dir, 'dependency-check-report.json')
                return_code = run_command(command)
                
                if return_code == 0 and os.path.exists(js_report_path):
                    parse_and_display_js_report(js_report_path, project_name)
                else:
                    print(f"{RENK_KIRMIZI}JavaScript taraması başarısız oldu (Hata Kodu: {return_code}).{RENK_RESET}")
                
                dirnames.clear()

    if found_projects == 0:
        print(f"{RENK_SARI}Belirtilen dizinde taranacak herhangi bir pom.xml veya package.json dosyası bulunamadı.{RENK_RESET}")

def main():
    parser = argparse.ArgumentParser(
        description='Bir dizindeki Java (Maven) ve JavaScript projelerini tarar.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('directory', help='Taranacak ana proje klasörünün yolu.')
    args = parser.parse_args()

    root_path = os.path.abspath(args.directory)
    if not os.path.isdir(root_path):
        print(f"{RENK_KIRMIZI}HATA: Belirtilen '{root_path}' yolu geçerli bir dizin değil.{RENK_RESET}")
        exit(1)

    find_and_scan_projects(root_path)
    
if __name__ == '__main__':
    main()

import os
import subprocess
import argparse

# Renk kodları (isteğe bağlı, konsol çıktısını güzelleştirir)
RENK_YESIL = '\033[92m'
RENK_MAVI = '\033[94m'
RENK_SARI = '\033[93m'
RENK_KIRMIZI = '\033[91m'
RENK_RESET = '\033[0m'

# Raporların kaydedileceği ana klasörün adı
REPORTS_BASE_DIR = "OWASP_Raporlari"

def run_scan(command, project_type, project_path):
    """
    Belirtilen dependency-check komutunu çalıştırır ve sonucu yazdırır.
    """
    project_name = os.path.basename(project_path)
    report_output_path = command[command.index('--out') + 1]

    print(f"{RENK_MAVI}► {project_type} projesi için tarama başlatılıyor: {project_name}{RENK_RESET}")
    print(f"  {RENK_SARI}Çalıştırılan Komut:{RENK_RESET} {' '.join(command)}")

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8')

        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(f"  {output.strip()}")

        return_code = process.poll()

        if return_code == 0:
            print(f"{RENK_YESIL}✔ Tarama başarıyla tamamlandı.{RENK_RESET}")
            print(f"  {RENK_YESIL}Rapor şuraya kaydedildi: {os.path.join(report_output_path, 'dependency-check-report.html')}{RENK_RESET}\n")
        else:
            print(f"{RENK_KIRMIZI}❌ Tarama sırasında bir hata oluştu: {project_name} (Hata Kodu: {return_code}){RENK_RESET}\n")

    except FileNotFoundError:
        print(f"{RENK_KIRMIZI}HATA: 'dependency-check' komutu bulunamadı.{RENK_RESET}")
        print("Lütfen OWASP Dependency-Check'in kurulu ve sistem PATH'ine ekli olduğundan emin olun.")
        exit(1)
    except Exception as e:
        print(f"{RENK_KIRMIZI}❌ Beklenmedik bir hata oluştu: {e}{RENK_RESET}\n")

def find_and_scan_projects(root_directory, scan_type):
    """
    Belirtilen dizinde seçilen proje türünü bulur ve tarar.
    """
    print(f"\nTaranacak ana dizin: {root_directory}")
    print(f"Aranan proje türü: {scan_type.upper()}\n")
    found_projects = 0

    for dirpath, dirnames, filenames in os.walk(root_directory):
        # Rapor klasörlerini, .git ve node_modules'in alt dizinlerini tekrar taramayı engelle
        dirnames[:] = [d for d in dirnames if d not in ['odc-report', '.git', REPORTS_BASE_DIR]]

        # 1. Java Projesi Taraması
        if scan_type == 'java' and 'target' in dirnames:
            dependency_dir = os.path.join(dirpath, 'target', 'dependency')
            if os.path.isdir(dependency_dir):
                found_projects += 1
                project_name = os.path.basename(dirpath)
                output_dir = os.path.join(REPORTS_BASE_DIR, f"{project_name}-java-report")

                command = [
                    'dependency-check',
                    '--project', project_name,
                    '--scan', dependency_dir,
                    '--format', 'HTML',
                    '--out', output_dir
                ]
                run_scan(command, "Java", dirpath)
                dirnames.clear()  # Alt dizinlere inmeye gerek yok

        # 2. JavaScript Projesi Taraması
        elif scan_type == 'js' and 'node_modules' in dirnames and 'package.json' in filenames:
            found_projects += 1
            project_name = os.path.basename(dirpath)
            scan_path = dirpath
            output_dir = os.path.join(REPORTS_BASE_DIR, f"{project_name}-js-report")

            # DEĞİŞİKLİK: Sadece JS analizi yapmak için Java ve diğer analizörler devre dışı bırakıldı.
            command = [
                'dependency-check',
                '--project', project_name,
                '--scan', scan_path,
                '--format', 'HTML',
                '--out', output_dir,
                '--disableJar',      # JAR dosyalarını analiz etme
                '--disableCentral',  # Maven Central analizini kapat
                '--disableAssembly'  # .NET analizini kapat (önlem olarak)
            ]
            run_scan(command, "JavaScript", dirpath)
            dirnames.clear() # Alt dizinlere inmeye gerek yok

    if found_projects == 0:
        print(f"{RENK_SARI}Belirtilen dizinde taranacak herhangi bir '{scan_type.upper()}' projesi bulunamadı.{RENK_RESET}")

def main():
    parser = argparse.ArgumentParser(
        description='OWASP Dependency-Check ile Java veya JavaScript projelerinde güvenlik açığı taraması yapar.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        'directory',
        help='Taramaya başlanacak ana proje klasörünün yolu.\nÖrnek: python3 dependency_scanner.py /Users/kullanici/projelerim'
    )
    args = parser.parse_args()

    root_path = os.path.abspath(args.directory)

    if not os.path.isdir(root_path):
        print(f"{RENK_KIRMIZI}HATA: Belirtilen '{root_path}' yolu geçerli bir dizin değil.{RENK_RESET}")
        exit(1)

    # Kullanıcıdan hangi tür tarama yapılacağını öğren
    while True:
        print(f"{RENK_MAVI}Hangi tür projeleri taramak istersiniz?{RENK_RESET}")
        print("  1: Java (.jar dosyaları için 'target/dependency')")
        print("  2: JavaScript ('node_modules' ve 'package.json')")
        choice = input("Seçiminiz (1 veya 2): ")

        if choice == '1':
            scan_type = 'java'
            break
        elif choice == '2':
            scan_type = 'js'
            break
        else:
            print(f"{RENK_KIRMIZI}Geçersiz seçim. Lütfen 1 veya 2 girin.{RENK_RESET}\n")

    # Raporlar için ana klasörü oluştur (varsa hata verme)
    os.makedirs(REPORTS_BASE_DIR, exist_ok=True)
    print(f"Raporlar '{os.path.abspath(REPORTS_BASE_DIR)}' klasörüne kaydedilecek.")

    find_and_scan_projects(root_path, scan_type)

if __name__ == '__main__':
    main()

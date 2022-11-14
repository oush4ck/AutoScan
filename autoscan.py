#!/usr/bin/python3
import sys, os, socket, subprocess, colorama, signal, time, re, cloudscraper
from bs4 import BeautifulSoup
from colorama import Fore, Back, Style

def signal_handler(key, frame):
	print (Fore.RED+"\n\n[!] Saliendo...\n"+Fore.WHITE)
	sys.exit(1)

signal = signal.signal(signal.SIGINT, signal_handler)

def installer():
    os.system("clear")
    install = input("Instalar herramientas necesarias o actualizarlas (y/n) >> ")
    if install == "y":
        print("\n")
        os.system("sudo apt-get update && sudo apt-get install -y figlet bat lolcat xclip metasploit-framework set rkhunter binutils readline-common libruby ruby ssl-cert unhide.rb mailutils chkrootkit libuv1-dev whois arp-scan sslscan sslyze nmap john whatweb curl sqlmap hashid hash-identifier netdiscover net-tools dsniff spiderfoot hosthunter emailharvester theharvester maltego steghide exiftool wpscan golang-go cmake gcc finalrecon && go install -v github.com/alpkeskin/mosint@latest")
        os.system("/home/$USER/go/bin/mosint set intelx c2a96ff7-08cf-4b74-bf22-6606a64c11f7 && /home/$USER/go/bin/mosint set hunter ab02ab2a2e6993873de879cb011d7f6c6308bf97")
        print(Fore.LIGHTBLUE_EX+"\n\n[*] Herramientas instaladas con éxito. Ya puedes ejecutar el script sin problemas.\n"+Fore.WHITE)
        sys.exit(0)
    elif install == "n":
        print(Fore.LIGHTYELLOW_EX+"\n[+] Ejecutando el script..."+Fore.WHITE)
        time.sleep(2)
    else:
        print(Fore.RED+"\n[!] Porfavor, escriba 'y' o 'n' (sin comillas). \n\n[!] Saliendo...\n\n"+Fore.WHITE)
        sys.exit(1)

def nmap_tcp():
    os.system("clear && figlet NMAP-TCP Scan | lolcat")
    ip = input(Fore.LIGHTGREEN_EX+Style.DIM+"\nIntroduce la IP a escanear >> "+Style.NORMAL+Fore.WHITE)
    print("\n")
    os.system("figlet Iniciando escaneo; sudo nmap -p- -sS --min-rate 5000 -vvv --open -n -Pn %s -oG allPortsTCP" % (ip))
    copy_tcp = input(Fore.LIGHTCYAN_EX+"\n\n ¿Desea copiar los puertos en el portapapeles? (y/n) >> "+Fore.WHITE)
    if copy_tcp == "y":
        os.system("cat allPortsTCP | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',' | xclip -sel clip")
        os.system("rm -rf allPortsTCP")
        print(Fore.GREEN+Style.BRIGHT+"\n[+] Puertos copiados correctamente en el portapapeles\n")
        sys.exit(0)
    else:
        os.system("rm -rf allPortsTCP")
        print(Fore.LIGHTYELLOW_EX+Style.DIM+"\n\n[-] Bien. Saliendo...\n"+Fore.WHITE+Style.NORMAL)
        sys.exit(0)

def nmap_udp():
    os.system("clear && figlet NMAP-UDP Scan | lolcat")
    ip = input(Fore.LIGHTCYAN_EX+Style.DIM+"\nIntroduce la IP a escanear >> "+Style.NORMAL+Fore.WHITE)
    print("\n")
    os.system("figlet Iniciando escaneo; sudo nmap -sU -p- --min-rate 10000 -n -Pn %s -oG allPortsUDP && clear" % (ip))
    print(Style.BRIGHT+Fore.LIGHTMAGENTA_EX+"[+] Puertos abiertos por UDP en la IP "+ip+":\n"+Style.NORMAL+Fore.WHITE)
    os.system("cat allPortsUDP | grep -oP '\d{1,5}/open/udp'; rm -rf allPortsUDP")
    print("\n")
    sys.exit(1)

def nmap_tcp_sCV():
    os.system("clear && figlet NMAP-TCP Recon | lolcat")
    ip = input(Fore.LIGHTMAGENTA_EX+Style.BRIGHT+"\nIntroduce la IP >> "+Style.NORMAL+Fore.WHITE)
    ports = input(Fore.LIGHTWHITE_EX+Style.DIM+"\nPuertos a lanzar los scripts básicos de enumeración y detección de servicios (separados entre comas [ , ]) >> "+Fore.WHITE+Style.NORMAL)
    save = input(Fore.LIGHTYELLOW_EX+Style.DIM+"\n¿Desea guardar el output final a un archivo? (y/n) >> "+Fore.WHITE+Style.NORMAL)
    if save == "y":
        file_to_save = input(Fore.YELLOW+Style.BRIGHT+"\nIndique el directorio donde guardar el archivo junto al nombre (ex. /home/user/targeted) >> "+Fore.WHITE+Style.NORMAL)
        os.system("nmap -sCV -p%s %s -oN %s" % (ports, ip, file_to_save))
        print(Fore.GREEN+Style.BRIGHT+"\n\n[+] Trabajo finalizado. Output guardado igualmente en %s" % (file_to_save))
        print(Fore.WHITE+Style.NORMAL)
        sys.exit(0)
    elif save == "n":
        os.system("nmap -sCV -p%s %s" % (ports, ip))
        print(Fore.GREEN+Style.BRIGHT+"\n\n[+] ¡Trabajo realizado con éxito!")
        sys.exit(0)
    else:
        print(Fore.LIGHTRED_EX+Style.DIM+"\n\n[!] Opción incorrecta")
        print("\n[!] Saliendo...\n\n"+Fore.WHITE+Style.NORMAL)

def nmap_udp_sCV():
    os.system("clear && figlet NMAP-UDP Recon | lolcat")
    ip = input(Fore.LIGHTMAGENTA_EX+Style.BRIGHT+"\nIntroduce la IP >> "+Style.NORMAL+Fore.WHITE)
    ports = input(Fore.LIGHTWHITE_EX+Style.DIM+"\nPuertos a lanzar los scripts básicos de enumeración y detección de servicios (separados entre comas [ , ]) >> "+Fore.WHITE+Style.NORMAL)
    save = input(Fore.LIGHTYELLOW_EX+Style.DIM+"\n¿Desea guardar el output final a un archivo? (y/n) >> "+Fore.WHITE+Style.NORMAL)
    if save == "y":
        file_to_save = input(Fore.YELLOW+Style.BRIGHT+"\nIndique el directorio donde guardar el archivo junto al nombre (ex. /home/user/targeted) >> "+Fore.WHITE+Style.NORMAL)
        os.system("sudo nmap -sU -sCV -p%s %s -oN %s" % (ports, ip, file_to_save))
        print(Fore.GREEN+Style.BRIGHT+"\n\n[+] Trabajo finalizado. Output guardado igualmente en %s" % (file_to_save))
        print(Fore.WHITE+Style.NORMAL)
        sys.exit(0)
    elif save == "n":
        os.system("nmap -sCV -p%s %s" % (ports, ip))
        print(Fore.GREEN+Style.BRIGHT+"\n\n[+] ¡Trabajo realizado con éxito!")
        sys.exit(0)
    else:
        print(Fore.LIGHTRED_EX+Style.DIM+"\n\n[!] Opción incorrecta")
        print("\n[!] Saliendo...\n\n"+Fore.WHITE+Style.NORMAL)

def arp_scan():
    os.system("clear && figlet ARP-Scan Localnet | lolcat")
    interface = input(Fore.BLUE+Style.BRIGHT+"Pon el nombre de la interfaz (ex. eth0) >> "+Fore.WHITE+Style.NORMAL)
    print("\n")
    os.system("sudo arp-scan -I %s --localnet" % (interface))

def ssl_scan():
    os.system("clear && figlet SSL Scan | lolcat")
    target = input(Fore.LIGHTMAGENTA_EX+Style.DIM+"\nDominio o IP a analizar >> "+Fore.WHITE+Style.NORMAL)
    print(Fore.LIGHTGREEN_EX+Style.BRIGHT+"\n\n[+] Iniciando análisis SSL...\n"+Fore.WHITE+Style.NORMAL)
    time.sleep(2)
    os.system("sslscan %s; sslyze %s" % (target, target))
    print(Fore.GREEN+Style.DIM+"\n\n[#] ¡Análisis finalizado con éxito!\n"+Fore.WHITE+Style.NORMAL)
    sys.exit(0)
    
def hash_id():
    os.system("clear && figlet Hash identifier| lolcat")
    hash = input(Fore.LIGHTWHITE_EX+Style.BRIGHT+"\nHash a identificar >> "+Fore.WHITE+Style.NORMAL)
    if len(set(hash)) >= 10:
        print("\n")
        os.system("echo '%s'|hash-identifier 2>/dev/null | grep -vE '#|-------| HASH: '" % (hash))
        print(Fore.MAGENTA+Style.DIM+"\n\n[#] ¡Hash identificado correctamente!\n"+Style.NORMAL+Fore.WHITE)
        sys.exit(0)
    else:
        print(Fore.RED+Style.BRIGHT+"\n\n[!] El formato del hash indicado es inválido.")
        print("\n[-] Saliendo...\n"+Fore.WHITE+Style.NORMAL)

def whatweb():
    os.system("clear && figlet Web recon | lolcat")
    url = input(Fore.LIGHTYELLOW_EX+"\nURL a escanear (ex. https://www.google.com/ ), si desea escanear mas URL's, sepáralos entre espacios (ex. https://www.google.es/ https://www.facebook.com/ http://192.168.1.1/) >> "+Fore.WHITE)
    print("\n")
    os.system("whatweb %s -a 3 -vv --no-errors -q" % (url))
    print(Fore.LIGHTCYAN_EX+Style.BRIGHT+"\n\n[+] ¡Fin del análisis!\n"+Fore.WHITE+Style.NORMAL)
    sys.exit(0)
    
def whois_scan():
    os.system("clear && figlet Enterprise recon | lolcat")
    domain = input(Fore.LIGHTBLUE_EX+Style.BRIGHT+"\nDominio de la empresa (ex. facebook.com ) >> "+Fore.WHITE+Style.NORMAL)
    print("\n")
    os.system("whois %s" % (domain))
    print(Fore.LIGHTYELLOW_EX+Style.DIM+"\n\n[+] Eso es todo. ¡Le recomiendo usar Maltego si desea obtener muchos mejores resultados y mucha mas información!\n"+Fore.WHITE+Style.NORMAL)
    sys.exit(0)

def emails_get():
    os.system("clear && figlet Get e-mails | lolcat")
    print(Style.BRIGHT+Fore.RED+"\n[!] USA ESTA UTILIDAD SOLO 1 VEZ POR HORA\n")
    time.sleep(2)
    domain = input(Fore.CYAN+Style.BRIGHT+"\nIntroduce el dominio de la empresa que quieras sacar los e-mails (ex. microsoft.com) >> "+Fore.WHITE+Style.NORMAL)
    print(Style.BRIGHT+"\n\n[**] ESPERE... ¡Esto podría demorarse hasta 15 minutos!\n\n"+Style.NORMAL)
    os.system("theHarvester -d %s -l 100 -b all | grep '@'; emailharvester -d %s -e all -l 100 | grep -i '@'" % (domain, domain))
    print(Fore.LIGHTGREEN_EX+Style.DIM+"\n\n[#] ¡Aquí tiene los resultados!\n"+Fore.WHITE+Style.NORMAL)
    sys.exit(0)
    
def waf_scan():
    os.system("clear && figlet WAF Scanner | lolcat")   
    domain = input(Style.BRIGHT+Fore.LIGHTRED_EX+"\nURL a escanear, si desea poner varios, sepárelos entre espacios (ex. https://www.microsoft.com/ https://www.amazon.com/ https://www.google.es/ ) >> "+Fore.WHITE+Style.NORMAL)
    os.system("wafw00f %s -a" % (domain))
    print(Fore.YELLOW+Style.BRIGHT+"\n\n[+] Detección de WAF's finalizado\n"+Fore.WHITE+Style.NORMAL)
    sys.exit(0)

def metadata_scan():
    os.system("clear && figlet Metadata scan | lolcat")
    file = input(Fore.MAGENTA+Style.BRIGHT+"\nArchivo para obtener los metadatos, si son varios sepárelos entre espacios (ex. /home/user/Descargas/file.pdf /home/user/Documentos/test.txt ) >> "+Fore.WHITE+Style.NORMAL)
    print("\n")
    os.system("exiftool %s" % (file))
    print(Fore.GREEN+Style.DIM+"\n\n[+] ¡Metadatos obtenidos correctamente!\n"+Fore.WHITE+Style.NORMAL)
    sys.exit(0)
   
def rootkit_scan():
    os.system("clear && figlet RootKit scanner | lolcat")
    print(Style.BRIGHT+"\n[+] Iniciando análisis y búsqueda de posibles RootKit's y virus presentes al equipo...\n\n"+Style.NORMAL)
    time.sleep(3)
    os.system("sudo chkrootkit; sudo rkhunter --update; sudo rkhunter --propupd; sudo rkhunter --check")
    time.sleep(2)
    print(Fore.LIGHTGREEN_EX+Style.BRIGHT+'\n\n[#] Proceso finalizado. Recuerda también que puedes revisar el archivo /var/log/rkhunter.log para estar 100% seguro del output recibido.'+Fore.WHITE+Style.NORMAL)
    sys.exit(0)

def wpscan():
    os.system("clear && figlet WordPress scan | lolcat")
    api = "O4RraJsOO4fuxbacAbmJs1Err02uQb8yeKMy63V44ic"
    url = input(Fore.RED+Style.DIM+"\nURL con WordPress a escanear (ex. https://www.example.com/ ) >> "+Fore.WHITE+Style.NORMAL)
    print(Style.BRIGHT+"\n[+] Recuerda que esto será un análisis bastante profundo, podría saturar el servidor...\n"+Style.NORMAL)
    time.sleep(2)
    os.system("wpscan --api-token '%s' --url %s --rua --disable-tls-checks -e vp,vt,cb,dbe,u" % (api, url))
    print(Fore.BLUE+Style.BRIGHT+"\n\n{$} ¡Análisis terminado!\n"+Fore.WHITE+Style.NORMAL)
    sys.exit(0)

def email_osint():
    os.system("clear && figlet E-mail Osint | lolcat")
    email = input(Fore.YELLOW+Style.BRIGHT+"\nE-mail a realizar OSINT (ex. tester25@example.com ) >> ")
    print(Style.DIM+Fore.RED+"\n[!] USA ESTO CON FINES ÉTICOS Y LEGALES !!!\n"+Style.NORMAL+Fore.WHITE)
    time.sleep(2)
    os.system("/home/$USER/go/bin/mosint %s" % (email))
    print(Fore.LIGHTBLUE_EX+Style.BRIGHT+"\n\n[+] Hecho."+Fore.WHITE+Style.NORMAL)
    sys.exit(0)

def fullwebrecon():
    os.system("clear && figlet Full Web Recon | lolcat")
    url = input(Fore.CYAN+Style.BRIGHT+"\nURL a realizar el análisis (casi) completo (ex. https://www.thisismysite.org/ ) >> "+Style.NORMAL+Fore.WHITE)
    print(Fore.RED+Style.DIM+"\n[!] ¡ESTA UTILIDAD ES MUY AGRESIVA! Úsala con precaución.\n\n"+Fore.WHITE+Style.NORMAL)
    time.sleep(3)
    os.system("finalrecon --full %s" % (url))
    print(Fore.GREEN+Style.BRIGHT+"\n\n[+] ¡Todo hecho correctamente!\n")
    sys.exit(0)

def file_analysis():
    os.system("clear && figlet File Analysis | lolcat")
    file = input(Fore.YELLOW+Style.BRIGHT+"\nArchivo con ruta completa a analizar (ex. /home/user/Documentos/file.exe ) >> "+Fore.WHITE+Style.NORMAL)
    print(Fore.LIGHTMAGENTA_EX+Style.DIM+"\n[!] Esta opción usa VirusTotal\n\n"+Fore.WHITE+Style.NORMAL)
    time.sleep(2)
    os.system("msf-virustotal -k 4eb844afcc814065483320dc724783cc323868c8a69e6d625a8f20eaa624f6ff -f %s" % (file))
    print(Fore.GREEN+Style.BRIGHT+"\n\n[+] Análisis finalizado...\n"+Fore.WHITE+Style.NORMAL)
    sys.exit(0)

installer()

os.system("clear && figlet AutoScan | lolcat")
print(Fore.LIGHTGREEN_EX+Style.BRIGHT+"Made by anmh4ck\n\n"+Style.NORMAL+Fore.WHITE)

print("[1] Escanear todo el rango de puertos por TCP usando nmap\n"
      "[2] Escanear todo el rango de puertos por UDP usando nmap\n"
      "[3] Lanzar scripts básicos de enumeración de servicios y versiones a puertos específicos por TCP (nmap)\n"
      "[4] Lanzar scripts básicos de enumeración de servicios y versiones a puertos específicos por UDP (nmap)\n"
      "[5] Saber qué dispositivos están conectados a la red local (arp-scan)\n"
      "[6] Analizar certificado SSL de una IP o dominio (sslscan & sslyze)\n"
      "[7] Analizar un hash (hash-identifier)\n"
      "[8] Aplicar reconocimiento básico en una página web (whatweb)\n"
      "[9] Obtener información sobre una empresa a través del dominio (whois)\n"
      "[10] Obtener e-mails de una empresa a través del dominio (theHarvester & emailharvester)\n"
      "[11] Averiguar el WAF que emplea un sitio web por detrás (wafw00f)\n"
      "[12] Ver metadatos y extraer información oculta de un archivo (exiftool)\n"
      "[13] Analizar el sistema en busca de virus y RootKit's que podrían estar presentes al equipo (chkrootkit & rkhunter)\n"
      "[14] Enumerar una página web hecha en WordPress (wpscan)\n"
      "[15] Realizar OSINT a una dirección e-mail (mosint)\n"
      "[16] Aplicar FULL análisis a un sitio web (finalrecon)\n"
      "[17] Analizar un archivo en busca de virus (msf-virustotal)"
      )

select = input(Style.DIM+Fore.MAGENTA+"\nSelecciona un número >> "+Style.NORMAL+Fore.WHITE)

if select == "1":
    nmap_tcp()
elif select == "2":
    nmap_udp()
elif select == "3":
    nmap_tcp_sCV()
elif select == "4":
    nmap_udp_sCV()
elif select == "5":
    arp_scan()
elif select == "6":
    ssl_scan()
elif select == "7":
    hash_id()
elif select == "8":
    whatweb()
elif select == "9":
    whois_scan()
elif select == "10":
    emails_get()
elif select == "11":
    waf_scan()
elif select == "12":
    metadata_scan()
elif select == "13":
    rootkit_scan()
elif select == "14":
    wpscan()
elif select == "15":
    email_osint()
elif select == "16":
    fullwebrecon()
elif select == "17":
    file_analysis()

else:
    print(Fore.RED+"\n[!] Opción incorrecta. Saliendo...\n"+Fore.WHITE)
    sys.exit(1)

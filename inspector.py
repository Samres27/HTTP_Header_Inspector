import requests
import argparse
import sys
import re
from colorama import Fore, Style
from collections import defaultdict

# Extraido de https://cpdos.org/#overview
TECH_MATRIX = {
    'ASP.NET': {
        'Varnish': {'HHO': True, 'HMC': False, 'HMO': False},
        'Akamai': {'HHO': True, 'HMC': False, 'HMO': False},
        'CDN77': {'HHO': True, 'HMC': False, 'HMO': False},
        'Cloudflare': {'HHO': True, 'HMC': False, 'HMO': False},
        'CloudFront': {'HHO': True, 'HMC': True, 'HMO': False},
        'Fastly': {'HHO': True, 'HMC': False, 'HMO': False}
    },
    
    "IIS": {
        "Varnish": {"HHO": True, "HMC": False, "HMO": False},
        "Akamai": {"HHO": True, "HMC": False, "HMO": False},
        "CDN77": {"HHO": True, "HMC": False, "HMO": False},
        "Cloudflare": {"HHO": True, "HMC": False, "HMO": False},
        "CloudFront": {"HHO": True, "HMC": True, "HMO": False},
        "Fastly": {"HHO": True, "HMC": False, "HMO": False}
    },
    "Apache HTTPD + (ModSecurity)": {
        "CloudFront": {"HHO": True, "HMC": True, "HMO": False}
    },
    "Nginx + (ModSecurity)": {
        "CloudFront": {"HHO": True, "HMC": False, "HMO": False}
    },
    "Tomcat": {
        "CloudFront": {"HHO": True, "HMC": False, "HMO": False}
    },
    "Varnish": {
        "CloudFront": {"HHO": True, "HMC": True, "HMO": False}
    },
    "Amazon S3": {
        "CloudFront": {"HHO": True, "HMC": False, "HMO": False}
    },
    "Github Pages": {
        "CloudFront": {"HHO": True, "HMC": True, "HMO": False}
    },
    "Gitlab Pages": {
        "CloudFront": {"HHO": False, "HMC": True, "HMO": False}
    },
    "Heroku": {
        "CloudFront": {"HHO": True, "HMC": False, "HMO": False}
    },
    
    "Beego": {
        "CloudFront": {"HHO": False, "HMC": True, "HMO": False}
    },
    "Django": {
        "CloudFront": {"HHO": True, "HMC": True, "HMO": False}
    },
    "Express.js": {
        "CloudFront": {"HHO": False, "HMC": True, "HMO": False}
    },
    "Flask": {
        "Akamai": {"HHO": False, "HMC": False, "HMO": True},
        "CloudFront": {"HHO": True, "HMC": True, "HMO": True}
    },
    "Gin": {
        "CloudFront": {"HHO": False, "HMC": True, "HMO": False}
    },
    "Laravel": {
        "CloudFront": {"HHO": True, "HMC": True, "HMO": False}
    },
    "Meteor.js": {
        "CloudFront": {"HHO": False, "HMC": True, "HMO": False}
    },
    "Play 1": {
        "Varnish": {"HHO": False, "HMC": False, "HMO": True},
        "Akamai": {"HHO": False, "HMC": False, "HMO": True},
        "CDN77": {"HHO": False, "HMC": False, "HMO": True},
        "Cloudflare": {"HHO": False, "HMC": False, "HMO": True},
        "CloudFront": {"HHO": True, "HMC": False, "HMO": True},
        "Fastly": {"HHO": False, "HMC": False, "HMO": True}
    },
    "Play 2": {
        "CloudFront": {"HHO": True, "HMC": True, "HMO": False}
    },
    "Rails": {
        "CloudFront": {"HHO": True, "HMC": True, "HMO": False}
    },
    "Spring Boot": {
        "CloudFront": {"HHO": True, "HMC": False, "HMO": False}
    },
    "Symfony": {
        "CloudFront": {"HHO": True, "HMC": True, "HMO": False}
    }

}

def cargar_wordlist(ruta_archivo):
    """Carga un archivo de wordlist con formato 'encabezado:valor'."""
    try:
        with open(ruta_archivo, 'r') as f:
            return dict(line.strip().split(':', 1) for line in f if ':' in line)

    except FileNotFoundError:
        print(f"[X] Error: Archivo '{ruta_archivo}' no encontrado.")
        return {}
           
def analizar_encabezados_y_recomendar(url,headers_personalizados=None):
    try:
        response = requests.get(url, headers=headers_personalizados, verify=False, timeout=10)
        encabezados = response.headers

        print(f"\n[A] Analizando encabezados de: {url}")
        print(f"[{Fore.GREEN}✓{Style.RESET_ALL}] Código de estado: {response.status_code}")

        
        print("\n=== Encabezados HTTP ===")
        for k, v in encabezados.items():
            #print(f"{k}: {v}")
            if k.lower() == 'server':
                print(f"{Fore.GREEN}{k}: {Fore.CYAN}{v}{Style.RESET_ALL}")
            elif k.lower().startswith('x-'):
                print(f"{Fore.MAGENTA}{k}: {Fore.WHITE}{v}{Style.RESET_ALL}")
            elif 'cookie' in k.lower():
                print(f"{Fore.RED}{k}: {Fore.YELLOW}{v}{Style.RESET_ALL}")
            else:
                print(f"{Fore.BLUE}{k}: {Fore.WHITE}{v}{Style.RESET_ALL}")

        
        print(f"\n=== {Fore.YELLOW}Encabezados personalizados (X-*){Style.RESET_ALL} ===")
        x_headers = [h for h in encabezados if h.startswith(('X-', 'x-'))]
        if x_headers:
            for h in x_headers:
                print(f"{Fore.BLUE}{h}{Style.RESET_ALL}: {encabezados[h]}")
        else:
            print("No se encontraron encabezados personalizados.")

        
        print(f"\n=== {Fore.YELLOW} Análisis del encabezado 'Vary'{Style.RESET_ALL} ===")
        if "Vary" in encabezados:
            print(f"Vary:{Fore.BLUE} {encabezados['Vary']}{Style.RESET_ALL}")
            if "X-Forwarded-Host" in encabezados["Vary"]:
                print("[W] Posible vulnerabilidad: 'Vary' incluye 'X-Forwarded-Host' (riesgo de cache poisoning).")
        else:
            print("No se encontró el encabezado 'Vary'.")
            
        return response
    except KeyboardInterrupt:
        print("\n[STOP] Ejecución interrumpida por el usuario (Ctrl+C).")
        sys.exit(0)
    
    except Exception as e:
        print(f"[X] Error: {e}")

def fuzzing_encabezados(url,fullFuzzing, ruteWordlist, response):
        
    modo="top10"
    common_headers_to_fuzz = {
        "Content-Type":"text/html; charset=UTF-8", 
        "X-Original-URL":"3421", 
        "Date":"Wed, 22 May 2025 14:00:00 GMT",
        "Server":"nginx/1.18.0 (Ubuntu)",
        "Connection":"keep-alive",
        "Cache-Control":"max-age=3600",
        "Last-Modified":"Wed, 22 May 2025 12:00:00 GMT",
        "ETag":"abc123def",
        "Accept-Ranges":"bytes",
        "Content-Encoding":"gzip"
    }
    if ruteWordlist != None:
        common_headers_to_fuzz=cargar_wordlist(ruta_archivo=ruteWordlist)
        modo="Diccionario propio"
    elif fullFuzzing:
        common_headers_to_fuzz=cargar_wordlist(ruta_archivo="Fuzz_headers.txt")
        modo="Full Fuzzing"
        
    print(f"\n==={Fore.YELLOW} Fuzzing de encabezados ({modo}) {Style.RESET_ALL}===")
    for header in common_headers_to_fuzz:
        try:
            
            test_response = requests.get(url, headers={header: "fuzz_value"}, verify=True, timeout=5)
            if test_response.status_code != response.status_code:
                print(f" El encabezado '{Fore.BLUE}{header}{Style.RESET_ALL}' afecta la respuesta (Código: {test_response.status_code}).")
        except KeyboardInterrupt:
                print("\n[STOP] Fuzzing interrumpido por el usuario (Ctrl+C).")
                
                sys.exit(0)  # Salir con código 0 (sin error)
                
        except:
            pass

    



# tabla sacada de https://cpdos.org/#overview


def detectar_cdn(headers):
    cdn_headers = {
        "Varnish": ["via: 1.1 varnish"],
        "Akamai": ["akamai-", "x-akamai"],
        "CDN77": ["cdn77-", "x-cdn","X-77-POP","X-77-Cache","X-77-NZT-Ray"],
        "Cloudflare": ["cf-ray", "cf-cache-status", "server: cloudflare","Cf-Connecting-IP","CF-EW-Via","CF-Pseudo-IPv4","CF-IPCountry","CDN-Loop","CF-Worker"],
        "CloudFront": ["x-amz-cf-", "via: 1.1 cloudfront","CloudFront-Viewer-Address","CloudFront-Viewer-Address","CloudFront-Viewer-Country-Region","CloudFront-Viewer-Header-Order"],
        "Fastly": ["fastly-cachetype", "x-cache", "x-fastly-request-id","fastly-"]
    }

    coincidencias_cdn = ""

    for cdn, patrones in cdn_headers.items():
        for clave, valor in headers.items():
            for patron in patrones:
                if patron.lower() in clave or patron.lower() in valor:
                    coincidencias_cdn=cdn
                    break

    return coincidencias_cdn if coincidencias_cdn else "No se detectó CDN conocido"

def identificar_tecnologia(headers, cookies):
    firmas = {
        "Apache HTTPD + (ModSecurity)": ["server:apache"],
        "Nginx + (ModSecurity)": ["server:nginx"],
        "IIS": ["server:microsoft-iis"],
        "Tomcat": ["server:apache-coyote"],
        "Varnish": ["via: 1.1 varnish","server:varnish"],
        "Amazon S3": ["server:amazons3", "x-amz-request-id"],
        "Google Cloud Storage": ["server:uploadserver", "x-goog-"],
        "Github Pages": ["server:github.com"],
        "Gitlab Pages": ["server:gitlab"],
        "Heroku": ["via: 1.1 vegur"],
        "ASP.NET": ["x-powered-by: asp.net"],
        "BeeGo": ["server:beegoserver"],
        "Django": ["server:gunicorn", "x-content-type-options", "x-frame-options"],
        "Express.js": ["x-powered-by: express"],
        "Flask": ["server:werkzeug"],
        "Gin": ["server:gin"],
        "Laravel": ["laravel_session", "x-powered-by: php"],
        "Meteor.js": ["server:meteor"],
        "Play 1": ["x-powered-by: play"],
        "Rails": ["x-runtime", "x-powered-by: phusion passenger"],
        "Spring Boot": ["x-application-context", "server:jetty", "server:apache tomcat"],
        "Symfony": ["x-debug-token", "x-powered-by: php"]
    }


    coincidencia = []

    for tecnologia, patrones in firmas.items():
        for patron in patrones:
            if ":" in patron:
                k, v = patron.split(":", 1)
                lower_dict = {
                key: value.lower() if isinstance(value, str) else value
                for key, value in headers.items()
}
                if k.lower() in lower_dict and v.lower() in headers[k].lower():
                    coincidencia=tecnologia
                    break
            else:
                # Buscar en cookies
                if any(patron in ck.lower() for ck in cookies.keys()):
                    coincidencia=tecnologia

    return coincidencia if coincidencia else "No se detectó tecnología conocida"



def detectar_tecnologias(url):
    """Detecta la tecnología del servidor y caché/CDN"""
    try:
        response = requests.get(url, timeout=5, verify=False)
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        cookies = response.cookies.get_dict()

        http_impl = identificar_tecnologia(headers=headers,cookies=cookies)
        cache_tech = detectar_cdn(headers=headers)
        return http_impl, cache_tech, headers
        
    except Exception as e:
        print(f"Error detecting technologies: {e}")
        return None, None, None

def revisar_cpdos_vulnerabilidades(http_impl, cache_tech):
    """Revisa vulnerabilidades CPDoS basado en la matriz"""
    if not http_impl or not cache_tech:
        return None
    
    # Buscar en la matriz principal
    for impl, cache_dict in TECH_MATRIX.items():
        if impl == http_impl:
            for cache, vulns in cache_dict.items():
                if cache == cache_tech:
                    return vulns
    
    # Si no se encuentra combinación exacta, buscar por implementación
    for impl, cache_dict in TECH_MATRIX.items():
        if impl.split(' +')[0] == http_impl.split(' +')[0]:
            for cache, vulns in cache_dict.items():
                if cache == cache_tech:
                    return vulns
    
    return {'HHO': False, 'HMC': False, 'HMO': False}



def analizar_cpdos(url):
    """Analiza URL para vulnerabilidades CPDoS con salida a color."""
    http_impl, cache_tech, headers = detectar_tecnologias(url)
    
    print(f"\n{Fore.YELLOW}🔍 Análisis de CPDoS para: {Fore.CYAN}{url}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}{'='*50}{Style.RESET_ALL}")
    
    if not http_impl:
        print(f"{Fore.RED}[✗] No se pudo determinar la implementación HTTP{Style.RESET_ALL}")
        return
    
    print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Implementación HTTP detectada: {Fore.GREEN}{http_impl}{Style.RESET_ALL}")
    
    if cache_tech:
        print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Tecnología de caché/CDN detectada: {Fore.MAGENTA}{cache_tech}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[i]{Style.RESET_ALL} No se detectó tecnología de caché/CDN")
    
    vulns = revisar_cpdos_vulnerabilidades(http_impl, cache_tech)
    
    print(f"\n{Fore.BLUE} Vulnerabilidades CPDoS potenciales:{Style.RESET_ALL}")
    print(f"HHO (HTTP Header Oversize): {Fore.GREEN if vulns['HHO'] else Fore.RED}[{'✓' if vulns['HHO'] else '✗'}]{Style.RESET_ALL}")
    print(f"HMC (HTTP Meta Character): {Fore.GREEN if vulns['HMC'] else Fore.RED}[{'✓' if vulns['HMC'] else '✗'}]{Style.RESET_ALL}")
    print(f"HMO (HTTP Method Override): {Fore.GREEN if vulns['HMO'] else Fore.RED}[{'✓' if vulns['HMO'] else '✗'}]{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN} Cabeceras relevantes:{Style.RESET_ALL}")
    for h in ['Server', 'X-Powered-By', 'Via', 'X-Cache', 'CF-Ray', 'X-Akamai']:
        if h in headers:
            print(f"{Fore.MAGENTA}{h}: {Fore.WHITE}{headers[h]}{Style.RESET_ALL}")
    

if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description="Analizador avanzado de encabezados HTTP")
        parser.add_argument("-u", "--url", help="URL a analizar", required=True)
        parser.add_argument("-H", "--header", help="Encabezado personalizado (ej: 'X-Forwarded-Host: ejemplo.com')", action="append")
        parser.add_argument("-FF", "--fullFuzzing",help="Realizar Fuzzing con todos los encabezados (por defecto 10)",action="store_true")
        parser.add_argument("-w", "--wordlist", help="Ruta a archivo de wordlist (formato 'encabezado:valor')")
        parser.add_argument("-CP", "--cachePoisoned", help="Analisis de Cache Poising",action="store_true")
        args = parser.parse_args()

        custom_headers = {}
        if args.header:
            for h in args.header:
                key, value = h.split(":", 1)
                custom_headers[key.strip()] = value.strip()

        response= analizar_encabezados_y_recomendar(args.url, custom_headers)
        fuzzing_encabezados(args.url,args.fullFuzzing,args.wordlist,response)
        if args.cachePoisoned : analizar_cpdos(args.url)
    
    except KeyboardInterrupt:
        print("\n[STOP] Programa detenido por el usuario (Ctrl+C).")
        sys.exit(0)
        

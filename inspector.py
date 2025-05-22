import requests
import argparse
import sys

def cargar_wordlist(ruta_archivo):
    """Carga un archivo de wordlist con formato 'encabezado:valor'."""
    try:
        with open(ruta_archivo, 'r') as f:
            return dict(line.strip().split(':', 1) for line in f if ':' in line)

    except FileNotFoundError:
        print(f"[❌] Error: Archivo '{ruta_archivo}' no encontrado.")
        return {}
           
def analizar_encabezados_y_recomendar(url,headers_personalizados=None):
    try:
        response = requests.get(url, headers=headers_personalizados, verify=False, timeout=10)
        encabezados = response.headers

        print(f"\n[A] Analizando encabezados de: {url}")
        print(f"[✓] Código de estado: {response.status_code}")

        
        print("\n=== Encabezados HTTP ===")
        for k, v in encabezados.items():
            print(f"{k}: {v}")

        
        print("\n=== Encabezados personalizados (X-*) ===")
        x_headers = [h for h in encabezados if h.startswith(('X-', 'x-'))]
        if x_headers:
            for h in x_headers:
                print(f"{h}: {encabezados[h]}")
        else:
            print("No se encontraron encabezados personalizados.")

        
        print("\n=== 🔄 Análisis del encabezado 'Vary' ===")
        if "Vary" in encabezados:
            print(f"Vary: {encabezados['Vary']}")
            if "X-Forwarded-Host" in encabezados["Vary"]:
                print("[W] Posible vulnerabilidad: 'Vary' incluye 'X-Forwarded-Host' (riesgo de cache poisoning).")
        else:
            print("No se encontró el encabezado 'Vary'.")
            
        return response
    except KeyboardInterrupt:
        print("\n[🛑] Ejecución interrumpida por el usuario (Ctrl+C).")
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
        
    print(f"\n=== Fuzzing de encabezados ({modo}) ===")
    for header in common_headers_to_fuzz:
        try:
            
            test_response = requests.get(url, headers={header: "fuzz_value"}, verify=False, timeout=5)
            if test_response.status_code != response.status_code:
                print(f" El encabezado '{header}' afecta la respuesta (Código: {test_response.status_code}).")
        except KeyboardInterrupt:
                print("\n[🛑] Fuzzing interrumpido por el usuario (Ctrl+C).")
                
                sys.exit(0)  # Salir con código 0 (sin error)
                
        except:
            pass

    

if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description="Analizador avanzado de encabezados HTTP")
        parser.add_argument("-u", "--url", help="URL a analizar", required=True)
        parser.add_argument("-H", "--header", help="Encabezado personalizado (ej: 'X-Forwarded-Host: ejemplo.com')", action="append")
        parser.add_argument("-FF", "--fullFuzzing",help="Realizar Fuzzing con todos los encabezados (por defecto 10)",action="store_true")
        parser.add_argument("-w", "--wordlist", help="Ruta a archivo de wordlist (formato 'encabezado:valor')")
        args = parser.parse_args()

        custom_headers = {}
        if args.header:
            for h in args.header:
                key, value = h.split(":", 1)
                custom_headers[key.strip()] = value.strip()

        response= analizar_encabezados_y_recomendar(args.url, custom_headers)
        fuzzing_encabezados(args.url,args.fullFuzzing,args.wordlist,response)
    
    except KeyboardInterrupt:
        print("\n[🛑] Programa detenido por el usuario (Ctrl+C).")
        sys.exit(0)
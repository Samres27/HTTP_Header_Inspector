
# HTTP Header Inspector 🔍

**Advanced HTTP Headers Analysis Tool**  
*Desarrollado por Samuel*  
📜 MIT Licensed | ⚠️ Solo para uso ético  

## Description
Herramienta Python para análisis de seguridad en encabezados HTTP que incluye:
- Detección de información sensible (Server, X-Powered-By)
- Identificación de vulnerabilidades CPDoS (Cache Poisoned Denial of Service)
- Análisis de riesgos en cabeceras HTTP
- Fuzzing de encabezados personalizados

## Installation
```bash
git clone git@github.com:Samres27/HTTP_Header_Inspector.git
cd HTTP_Header_Inspector
pip install -r requirements.txt
```

## Usage
```bash
# Análisis básico
python3 inspector.py -u https://example.com

# Detección de CPDoS
python3 inspector.py -u https://example.com -CP

# Fuzzing con wordlist personalizada
python3 inspector.py -u https://example.com -w headers_wordlist.txt

# Modo completo (100+ cabeceras)
python3 inspector.py -u https://example.com -FF
```

## Options

| Argumento | Descripción |
|-----------|-------------|
| `-u URL`, `--url URL` | **URL objetivo** para analizar (requerido). |
| `-s`, `--scan` | Habilita el **modo de escaneo** (sin argumentos adicionales para ataques específicos). |
| `-H CUSTOM_HEADER`, `--header CUSTOM_HEADER` | **Añade encabezados HTTP personalizados** a la solicitud (ej: `'X-Forwarded-Host: ejemplo.com'`). Puedes usarlo varias veces para añadir múltiples encabezados. |
| `-FF`, `--fullFuzzing` | Realiza un **fuzzing completo** de todos los encabezados HTTP. Por defecto, prueba 10 combinaciones por encabezado. |
| `-w FILE_PATH`, `--wordlist FILE_PATH` | Especifica la **ruta a un archivo wordlist**. El archivo debe contener encabezados en el formato `nombre_cabecera:valor`. |
| `-CP`, `--cachePoisoned` | Habilita el **análisis para detectar vulnerabilidades de Cache Poisoning (CPDoS)**. |
| `-eHHO PAYLOAD_SIZE`, `--exploitHHO PAYLOAD_SIZE` | Activa la **explotación de HTTP Header Oversize (HHO)**. Debes especificar el tamaño de la carga (payload) en bytes. |
| `-eHMO`, `--exploitHMO` | Activa la **explotación de HTTP Method Override (HMO)**. Se requiere usar `-H` para especificar el encabezado `X-HTTP-Method-Override` y el método. |
| `-eHMC METACHARACTER_VALUE`, `--exploitHMC METACHARACTER_VALUE` | Activa la **explotación de HTTP Meta Character (HMC)**. Debes pasar el valor del metacaracter a inyectar (ej: `'x\x99'`). |

## Detección de CPDoS
El parámetro `-CP` analiza estas vulnerabilidades:

| Vulnerabilidad | Descripción | Técnica de explotación |
|---------------|-------------|------------------------|
| **HHO** (HTTP Header Oversize) | Cabeceras sobredimensionadas causan errores cacheados | Enviar cabeceras > 8KB |
| **HMC** (HTTP Meta Character) | Caracteres especiales malformados en cabeceras | Usar caracteres como \x00, \n, \r |
| **HMO** (HTTP Method Override) | Sustitución de métodos HTTP vía cabeceras | Usar X-HTTP-Method-Override |

Ejemplo de salida:
```
🔍 Análisis CPDoS para: https://example.com
✅ Tecnología detectada: Nginx + Cloudflare

📊 Vulnerabilidades:
[✔️] HHO - Cabeceras grandes (Cloudflare)
[✔️] HMC - Caracteres especiales (Nginx)
[❌] HMO - Métodos HTTP
```

## Sample Wordlist
`headers_wordlist.txt`:
```
X-Forwarded-Host: evil.com
X-HTTP-Method-Override: PUT
X-Original-URL: /admin
```

## Features
- ✔️ Detección automática de tecnologías (servidor + caché)
- ✔️ Análisis de vulnerabilidades CPDoS (HHO, HMC, HMO)
- ✔️ Fuzzing personalizable con wordlists
- ✔️ Interrupción segura con Ctrl+C


## License
MIT License - Ver [LICENSE](LICENSE) para detalles.

⚠️ **Advertencia**:  
Esta herramienta debe usarse solo en sistemas con permiso explícito. El uso no autorizado es ilegal.

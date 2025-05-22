
# HTTP Header Inspector 🔍

**Advanced HTTP Headers Analysis Tool**  
*Desarrollado por Samuel*  
📜 MIT Licensed | ⚠️ Solo para el uso etico 

## Description
`HTTP Header Inspector` es una herramienta python para el analisis de vulnerabilidades incluyendo:
- Informacion sensible del servidor (Server, X-Powered-By)
- Riesgos de envenenamiento de caché 
- Vulnerabilidades de encabezado

## Installation
```bash
git clone git@github.com:Samres27/HTTP_Header_Inspector.git
cd HTTP_Header_Inspector
pip install -r requirements.txt
```

## Usage
```bash
# Basic header analysis
python3 inspector.py -u https://example.com

# Custom header testing
python3 inspector.py -u https://example.com -H "X-Forwarded-Host: test.com"

# Advanced fuzzing with wordlist
python3 inspector.py -u https://example.com -w headers_wordlist.txt

# Full fuzzing mode (100+ headers)
python3 inspector.py -u https://example.com -FF
```

## Options
| Argument | Description |
|----------|-------------|
| `-u URL` | Target URL (required) |
| `-H` | Add custom headers |
| `-w` | Use wordlist file (header:value format) |
| `-FF` | Enable full fuzzing mode |

## Sample Wordlist
Create `headers_wordlist.txt`:
```
X-Forwarded-Host: evil.com
X-Rewrite-URL: /admin
Authorization: Bearer 123
```

## Features
- ✔️ Detección de encabezados sensibles
- ✔️ Análisis de riesgo de encabezados variables
- ✔️ Fuzzing personalizable
- ✔️ Interrupción segura con Ctrl+C
- ✔️ Compatibilidad con proxy (próximamente)

## License
Este proyecto esta bajo la licencia MIT - Ver [LICENSE](LICENSE) para detalles0.

⚠️ **Advertencia**: Úselo solo en sistemas autorizados.

---


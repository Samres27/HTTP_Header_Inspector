import socket

# Datos de la petición
host = "localhost"
#port = 8080
port= 3128
# Construir la petición con el metacaracter en el header
# Nota: \n y \r son literales reales, no escapados
# La cabecera termina con \r\n, luego el header "malformado" con \n, y otro header
request = (
    "GET /metacaracter-header HTTP/1.1\r\n"
    "Host: localhost:8000\r\n"
    "User-Agent: Custom-Python\r\n"
    "Accept: */*\r\n"
    "Set-cookie: poisno\aned\r\n"  # Aquí metemos el \n en medio de la cabecera

)

# Conexión al servidor
with socket.create_connection((host, port)) as sock:
    sock.sendall(request.encode())
    print("==== Petición enviada ====")
    print(request)
    print("==========================")

    # Leer la respuesta (opcional)
    response = sock.recv(4096)
    print("==== Respuesta ====")
    print(response.decode(errors='replace'))

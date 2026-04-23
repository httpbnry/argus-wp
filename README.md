# 👁️ Argus-WP

**Argus-WP** es una herramienta avanzada de auditoría y recolección de información (Information Gathering) especializada en entornos WordPress. Diseñada como proyecto principal para el TFG del grado ASIR (Administración de Sistemas Informáticos en Red).

> 💡 **Autoría**: httpbnry / jdb

---

## 🚀 Características Principales

1. **Reconocimiento Pasivo y Detección WAF**: Detecta si el sitio web está ejecutando WordPress y analiza sus cabeceras para descubrir si está protegido por un Web Application Firewall (Cloudflare, Wordfence, Sucuri).
2. **Enumeración de Entorno**: Extrae activamente los plugins instalados y el tema activo leyendo las etiquetas del código fuente, así como sus versiones.
3. **Escáner de Vulnerabilidades (CI/CD Mirror)**: Realiza un cruce de datos instantáneo y local de los plugins detectados utilizando la base de datos de inteligencia de vulnerabilidades descargada desde tu mirror de GitHub.
4. **Exportación de Reportes**: Genera completos reportes automatizados de auditoría en formatos legibles (TXT) o estructurados (JSON).

### 💣 Módulos de Ataque (Activos)
*   **Fuzzing de Backups (`--fuzz`)**: Rastrea el servidor en busca de archivos críticos mal asegurados (como `.env`, `wp-config.php.bak`, `debug.log`) y comprueba si hay *Directory Listing* expuesto.
*   **Escáner XML-RPC (`--xmlrpc`)**: Realiza inyecciones a la API XML-RPC de WordPress para descubrir si el vector de ataque por amplificación DDoS está disponible.
*   **Fuerza Bruta Multihilo (`-b`)**: Extrae usuarios válidos a través del endpoint REST API (`/wp-json/wp/v2/users`) y lanza un potente ataque de diccionario automatizado usando *ThreadPoolExecutor* para probar credenciales concurrentemente a altísima velocidad.

---

## 🛠️ Instalación

1. Clona el repositorio:
   ```bash
   git clone https://github.com/httpbnry/argus-wp.git
   cd argus-wp
   ```

2. Instala los requerimientos:
   ```bash
   pip install -r requirements.txt
   ```

3. Dale permisos de ejecución:
   ```bash
   chmod +x argus-wp.py
   ```

---

## 💻 Uso de la Herramienta

### Escaneo Básico (Seguro / Pasivo)
```bash
./argus-wp.py ejemplo.com
```

### Escaneo Completo y Exportación
```bash
./argus-wp.py ejemplo.com --update-db -o reporte_auditoria.txt -f txt
```

### Escaneo con Todos los Módulos Activos (RUIDOSO)
⚠️ **Advertencia:** Los módulos activos enviarán decenas de peticiones anómalas. Uso exclusivo para entornos con autorización.
```bash
./argus-wp.py ejemplo.com --xmlrpc --fuzz -b
```

---
*Desarrollado con ♥ para el Trabajo de Fin de Grado (ASIR).*

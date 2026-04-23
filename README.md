# 👁️ Argus-WP

**Argus-WP** es una herramienta avanzada de auditoría y recolección de información (Information Gathering) especializada en entornos WordPress. Diseñada como proyecto principal para el TFG del grado ASIR (Administración de Sistemas Informáticos en Red).

> 💡 **Autoría**: httpbnry / jdb

---

## 🚀 Características Principales

1. **Reconocimiento Pasivo**: Detecta si el sitio web está ejecutando WordPress sin interactuar agresivamente con el servidor.
2. **Enumeración de Entorno**: Extrae activamente los plugins instalados y el tema activo leyendo las etiquetas del código fuente, así como sus versiones.
3. **Detección de Information Disclosure (API REST)**: Identifica si el endpoint `/wp-json/wp/v2/users` está expuesto, recolectando los nombres de usuario y *slugs* válidos.
4. **Escáner de Vulnerabilidades (CI/CD Mirror)**: Realiza un cruce de datos instantáneo y local de los plugins detectados utilizando la base de datos de inteligencia de vulnerabilidades. Esto funciona sin necesidad de API Keys por parte del usuario final gracias a una infraestructura basada en *GitHub Actions* que actualiza la base de datos de manera transparente todos los días.
5. **Módulo de Fuerza Bruta Intrusiva**: Permite (mediante bandera explicita) realizar ataques de fuerza bruta al panel `wp-login.php` contra todos los usuarios extraídos, utilizando un diccionario de contraseñas de las más comunes.

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
   *(Dependencias principales: `requests`, `beautifulsoup4`, `colorama`)*

3. Dale permisos de ejecución:
   ```bash
   chmod +x argus-wp.py
   ```

---

## 💻 Uso de la Herramienta

Argus-WP corrige automáticamente los prefijos (intenta HTTPS y cae a HTTP si no está disponible), por lo que basta con pasarle el dominio.

### 1. Escaneo Básico (Reconocimiento)
```bash
./argus-wp.py ejemplo.com
```

### 2. Escaneo con Actualización de Vulnerabilidades
Para asegurarse de que tienes los últimos *exploits* listados:
```bash
./argus-wp.py ejemplo.com --update-db
```
> Esto descargará o actualizará automáticamente el archivo `wordfence_vulndb.json` en tu carpeta `db/`.

### 3. Escaneo Agresivo (Fuerza Bruta)
⚠️ **Advertencia:** Uso exclusivo para entornos controlados o con autorización previa.
```bash
./argus-wp.py ejemplo.com -b
```

---

## 🏗️ Arquitectura CI/CD

El módulo de vulnerabilidades no requiere que el analista se registre en servicios de terceros (como WPScan). Argus-WP incluye un flujo de trabajo (`workflow.yml`) alojado en GitHub Actions que extrae diariamente la base de datos de **Wordfence Intelligence V3**, y la sirve como un *Mirror Público*. 

Cuando ejecutas la bandera `--update-db`, Argus-WP descarga este *mirror* en milisegundos y cruza los CVEs localmente.

---
*Desarrollado con ♥ para el Trabajo de Fin de Grado (ASIR).*

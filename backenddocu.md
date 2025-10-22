# 📚 Documentación Técnica del Backend - USACLinux Remote Desktop

## 📋 Índice
1. [Arquitectura General](#arquitectura-general)
2. [Estructura de Archivos](#estructura-de-archivos)
3. [Flujo de Autenticación](#flujo-de-autenticación)
4. [Sistema de Sesiones](#sistema-de-sesiones)
5. [Endpoints de la API](#endpoints-de-la-api)
6. [Integración con Syscalls](#integración-con-syscalls)
7. [Manejo de Datos POST](#manejo-de-datos-post)
8. [Seguridad y Permisos](#seguridad-y-permisos)

---

## 🏗️ Arquitectura General

### Stack Tecnológico
```
┌─────────────────────────────────────────┐
│         Cliente (Navegador)             │
│    JavaScript/React en puerto 3000      │
└─────────────────┬───────────────────────┘
                  │ HTTP/JSON
                  │ (Bearer Token)
┌─────────────────▼───────────────────────┐
│      Backend C (puerto 8080)            │
│    • libmicrohttpd (HTTP server)        │
│    • json-c (JSON parsing)              │
│    • PAM (autenticación Linux)          │
│    • uuid (generación de tokens)        │
└─────────────────┬───────────────────────┘
                  │ syscall()
┌─────────────────▼───────────────────────┐
│         Kernel Linux 6.12.41            │
│    • sys_move_mouse (555)               │
│    • sys_send_key_event (556)           │
│    • sys_get_cpu_usage (558)            │
│    • sys_get_mem_usage (559)            │
│    • sys_capture_screen (550)           │
└─────────────────────────────────────────┘
```

### Componentes Principales

1. **Servidor HTTP**: libmicrohttpd
   - Servidor HTTP embebido en C
   - Maneja múltiples conexiones concurrentes
   - Soporte para métodos GET y POST

2. **Autenticación**: PAM (Pluggable Authentication Modules)
   - Integración directa con usuarios del sistema Linux
   - Validación de contraseñas segura
   - Verificación de membresía en grupos

3. **Manejo de JSON**: json-c
   - Parsing de peticiones JSON
   - Generación de respuestas JSON
   - Manipulación de objetos JSON

4. **Sesiones**: UUID v4
   - Tokens únicos de 128 bits
   - Timeout de 1 hora (3600 segundos)
   - Almacenamiento en memoria

---

## 📁 Estructura de Archivos

```
backend/
├── main.c           # Servidor HTTP, routing, handlers
├── auth.c           # Autenticación PAM y gestión de sesiones
├── auth.h           # Definiciones de estructuras de sesión
├── syscalls.c       # Wrappers para syscalls del kernel
├── syscalls.h       # Definiciones de estructuras de syscalls
├── config.h         # Constantes y configuración
├── Makefile         # Compilación del proyecto
└── usaclinux_api    # Binario ejecutable (generado)
```

---

## 🔐 Flujo de Autenticación

### 1. Proceso de Login

```
┌──────────┐                ┌──────────┐                ┌──────────┐
│ Cliente  │                │ Backend  │                │   PAM    │
└────┬─────┘                └────┬─────┘                └────┬─────┘
     │                           │                           │
     │ POST /api/auth/login      │                           │
     ├──────────────────────────►│                           │
     │ {username, password}      │                           │
     │                           │ pam_start()               │
     │                           ├──────────────────────────►│
     │                           │                           │
     │                           │ pam_authenticate()        │
     │                           ├──────────────────────────►│
     │                           │                           │
     │                           │◄──────────────────────────┤
     │                           │ PAM_SUCCESS               │
     │                           │                           │
     │                           │ check_user_permissions()  │
     │                           │ (verifica grupos)         │
     │                           │                           │
     │                           │ uuid_generate()           │
     │                           │ create_session()          │
     │                           │                           │
     │◄──────────────────────────┤                           │
     │ {token, permissions}      │                           │
     │                           │                           │
```

### 2. Código del Proceso (auth.c)

```c
// Paso 1: Normalizar el username
char username_lower[256];
strncpy(username_lower, username, sizeof(username_lower) - 1);
for (char *p = username_lower; *p; p++) {
    *p = tolower(*p);  // Convertir a minúsculas
}

// Paso 2: Configurar PAM
struct pam_conv conv = {
    .conv = pam_conversation,
    .appdata_ptr = password
};

// Paso 3: Iniciar PAM
pam_handle_t *pamh = NULL;
int ret = pam_start("login", username_lower, &conv, &pamh);

// Paso 4: Autenticar
ret = pam_authenticate(pamh, 0);
if (ret != PAM_SUCCESS) {
    return 0;  // Autenticación fallida
}

// Paso 5: Validar cuenta
ret = pam_acct_mgmt(pamh, 0);

// Paso 6: Limpiar
pam_end(pamh, ret);
```

### 3. Verificación de Permisos

```c
int check_user_permissions(const char *username, 
                          int *has_view, 
                          int *has_control) {
    struct group *remote_view = getgrnam("remote_view");
    struct group *remote_control = getgrnam("remote_control");
    
    // Verificar membresía en grupos
    for (int i = 0; remote_view->gr_mem[i] != NULL; i++) {
        if (strcmp(remote_view->gr_mem[i], username) == 0) {
            *has_view = 1;
        }
    }
    
    for (int i = 0; remote_control->gr_mem[i] != NULL; i++) {
        if (strcmp(remote_control->gr_mem[i], username) == 0) {
            *has_control = 1;
        }
    }
}
```

---

## 🎫 Sistema de Sesiones

### Estructura de Sesión

```c
typedef struct {
    char token[37];              // UUID string (36 chars + \0)
    char username[256];          // Nombre de usuario
    time_t created_at;           // Timestamp de creación
    time_t last_access;          // Último acceso
    int has_view_permission;     // Permiso de visualización
    int has_control_permission;  // Permiso de control
} session_t;
```

### Ciclo de Vida de una Sesión

```
1. CREACIÓN
   ├─ Usuario hace login exitoso
   ├─ Se genera UUID único: uuid_generate_random()
   ├─ Se crea session_t con timestamp actual
   └─ Se almacena en array sessions[]

2. VALIDACIÓN (en cada petición)
   ├─ Se extrae token del header "Authorization: Bearer <token>"
   ├─ Se busca sesión en el array
   ├─ Se verifica timeout (3600 segundos)
   │  └─ Si expiró: return false
   ├─ Se actualiza last_access
   └─ return true

3. EXPIRACIÓN
   ├─ Timeout automático: 1 hora sin actividad
   └─ Sesión se marca como inválida
```

### Código de Validación

```c
int validate_session(const char *token) {
    if (!token) return 0;
    
    // Buscar sesión
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].token[0] != '\0' && 
            strcmp(sessions[i].token, token) == 0) {
            
            time_t now = time(NULL);
            
            // Verificar timeout
            if (now - sessions[i].last_access > SESSION_TIMEOUT) {
                // Sesión expirada
                memset(&sessions[i], 0, sizeof(session_t));
                return 0;
            }
            
            // Actualizar último acceso
            sessions[i].last_access = now;
            return 1;
        }
    }
    
    return 0;  // Sesión no encontrada
}
```

---

## 🌐 Endpoints de la API

### 1. POST /api/auth/login

**Descripción**: Autentica un usuario y crea una sesión

**Request**:
```json
{
  "username": "joshi",
  "password": "mipassword"
}
```

**Response** (éxito):
```json
{
  "success": true,
  "token": "550e8400-e29b-41d4-a716-446655440000",
  "username": "joshi",
  "permissions": {
    "view": true,
    "control": true
  }
}
```

**Response** (error):
```json
{
  "success": false,
  "error": "Credenciales inválidas"
}
```

**Código del Handler**:
```c
static enum MHD_Result handle_login(struct MHD_Connection *connection,
                                   struct connection_info *con_info) {
    // 1. Verificar que hay datos
    if (con_info == NULL || con_info->data == NULL) {
        return send_json_response(connection, 400, error_response);
    }
    
    // 2. Parsear JSON
    json_object *request = json_tokener_parse(con_info->data);
    json_object *username_obj, *password_obj;
    json_object_object_get_ex(request, "username", &username_obj);
    json_object_object_get_ex(request, "password", &password_obj);
    
    const char *username = json_object_get_string(username_obj);
    const char *password = json_object_get_string(password_obj);
    
    // 3. Autenticar con PAM
    if (!authenticate_user(username, password)) {
        return send_json_response(connection, 401, error_response);
    }
    
    // 4. Verificar permisos
    int has_view = 0, has_control = 0;
    check_user_permissions(username, &has_view, &has_control);
    
    // 5. Crear sesión
    char token[37];
    create_session(username, has_view, has_control, token);
    
    // 6. Construir respuesta
    json_object *response = json_object_new_object();
    json_object_object_add(response, "success", json_object_new_boolean(1));
    json_object_object_add(response, "token", json_object_new_string(token));
    // ...
    
    return send_json_response(connection, 200, response);
}
```

---

### 2. GET /api/monitor/stats

**Descripción**: Obtiene estadísticas del sistema (CPU y RAM)

**Headers**:
```
Authorization: Bearer <token>
```

**Response**:
```json
{
  "cpu_usage": 45,
  "memory_usage": 68,
  "timestamp": 1729632000
}
```

**Código del Handler**:
```c
static enum MHD_Result handle_stats(struct MHD_Connection *connection,
                                   const char *token) {
    json_object *response = json_object_new_object();
    
    // 1. Validar sesión
    if (!validate_session(token)) {
        json_object_object_add(response, "error", 
                              json_object_new_string("Sesión inválida"));
        return send_json_response(connection, 401, response);
    }
    
    // 2. Llamar syscalls
    int cpu = get_cpu_usage();    // syscall 558
    int ram = get_mem_usage();    // syscall 559
    
    // 3. Construir respuesta
    json_object_object_add(response, "cpu_usage", json_object_new_int(cpu));
    json_object_object_add(response, "memory_usage", json_object_new_int(ram));
    json_object_object_add(response, "timestamp", 
                          json_object_new_int64(time(NULL)));
    
    return send_json_response(connection, 200, response);
}
```

**Wrapper de Syscall** (syscalls.c):
```c
int get_cpu_usage(void) {
    long result = syscall(SYS_GET_CPU_USAGE);  // 558
    if (result < 0) {
        perror("syscall get_cpu_usage");
        return -1;
    }
    return (int)result;
}
```

---

### 3. GET /api/remote/screen

**Descripción**: Captura la pantalla y la devuelve como imagen BMP

**Headers**:
```
Authorization: Bearer <token>
```

**Response**: 
- Content-Type: `image/bmp`
- Body: Imagen BMP (raw binary data)

**Proceso Detallado**:

```
1. CAPTURA DEL KERNEL
   ├─ syscall(550, buffer) → sys_capture_screen
   ├─ Kernel captura framebuffer
   ├─ Retorna: metadata + píxeles RGB
   └─ Formato: struct cap_buffer

2. CONVERSIÓN A BMP
   ├─ Crear header BMP (14 bytes)
   │  ├─ Signature: "BM"
   │  ├─ File size
   │  └─ Offset to pixel data
   ├─ Crear info header (40 bytes)
   │  ├─ Width, Height
   │  ├─ Bits per pixel: 24
   │  └─ Compression: 0 (none)
   └─ Agregar pixel data con padding

3. ENVÍO AL CLIENTE
   ├─ Content-Type: image/bmp
   ├─ Content-Length: tamaño total
   └─ Body: BMP completo
```

**Código del Handler**:
```c
static enum MHD_Result handle_screen(struct MHD_Connection *connection,
                                    const char *token) {
    // 1. Validar sesión
    if (!validate_session(token)) {
        return send_json_response(connection, 401, error);
    }
    
    // 2. Alocar buffer para captura
    size_t buffer_size = 8 * 1024 * 1024;  // 8 MB
    struct cap_buffer *cap = malloc(buffer_size);
    
    // 3. Llamar syscall de captura
    if (capture_screen(cap, buffer_size) != 0) {
        free(cap);
        return send_json_response(connection, 500, error);
    }
    
    // 4. Convertir a BMP
    size_t bmp_size;
    uint8_t *bmp_data = create_bmp(cap, &bmp_size);
    
    // 5. Enviar respuesta
    struct MHD_Response *response = MHD_create_response_from_buffer(
        bmp_size, bmp_data, MHD_RESPMEM_MUST_FREE
    );
    
    MHD_add_response_header(response, "Content-Type", "image/bmp");
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    
    int ret = MHD_queue_response(connection, 200, response);
    MHD_destroy_response(response);
    
    free(cap);
    return ret;
}
```

**Función de Conversión BMP**:
```c
static uint8_t* create_bmp(struct cap_buffer *cap, size_t *out_size) {
    uint32_t width = cap->meta.width;
    uint32_t height = cap->meta.height;
    
    // Calcular padding (cada fila debe ser múltiplo de 4)
    uint32_t row_size = ((width * 3 + 3) / 4) * 4;
    uint32_t pixel_data_size = row_size * height;
    
    // Tamaño total = headers + pixels
    *out_size = 14 + 40 + pixel_data_size;
    uint8_t *bmp = malloc(*out_size);
    
    // BMP File Header (14 bytes)
    bmp[0] = 'B'; bmp[1] = 'M';  // Signature
    *(uint32_t*)(bmp + 2) = *out_size;     // File size
    *(uint32_t*)(bmp + 6) = 0;             // Reserved
    *(uint32_t*)(bmp + 10) = 54;           // Offset to pixel data
    
    // BMP Info Header (40 bytes)
    *(uint32_t*)(bmp + 14) = 40;           // Header size
    *(int32_t*)(bmp + 18) = width;         // Width
    *(int32_t*)(bmp + 22) = height;        // Height
    *(uint16_t*)(bmp + 26) = 1;            // Planes
    *(uint16_t*)(bmp + 28) = 24;           // Bits per pixel
    *(uint32_t*)(bmp + 30) = 0;            // Compression
    *(uint32_t*)(bmp + 34) = pixel_data_size; // Image size
    
    // Copiar píxeles (invertir Y porque BMP va de abajo a arriba)
    for (uint32_t y = 0; y < height; y++) {
        uint32_t src_row = height - 1 - y;
        uint8_t *dst = bmp + 54 + (y * row_size);
        uint8_t *src = cap->data + (src_row * cap->meta.pitch0);
        
        for (uint32_t x = 0; x < width; x++) {
            // Convertir RGBA a BGR
            dst[x*3 + 0] = src[x*4 + 2];  // B
            dst[x*3 + 1] = src[x*4 + 1];  // G
            dst[x*3 + 2] = src[x*4 + 0];  // R
        }
        
        // Agregar padding
        memset(dst + width*3, 0, row_size - width*3);
    }
    
    return bmp;
}
```

---

### 4. POST /api/remote/mouse

**Descripción**: Controla el mouse (movimiento y clicks)

**Request** (movimiento):
```json
{
  "action": "move",
  "x": 16384,
  "y": 8192
}
```

**Request** (click):
```json
{
  "action": "click_left",
  "x": 0,
  "y": 0
}
```

**Response**:
```json
{
  "success": true
}
```

**Código del Handler**:
```c
static enum MHD_Result handle_mouse(struct MHD_Connection *connection,
                                   const char *token,
                                   struct connection_info *con_info) {
    json_object *response = json_object_new_object();
    
    // 1. Validar sesión y permisos
    if (!validate_session(token)) {
        return send_json_response(connection, 401, error);
    }
    
    session_t *session = get_session(token);
    if (!session->has_control_permission) {
        return send_json_response(connection, 403, error);
    }
    
    // 2. Parsear JSON
    json_object *request = json_tokener_parse(con_info->data);
    json_object *action_obj, *x_obj, *y_obj;
    json_object_object_get_ex(request, "action", &action_obj);
    json_object_object_get_ex(request, "x", &x_obj);
    json_object_object_get_ex(request, "y", &y_obj);
    
    const char *action_str = json_object_get_string(action_obj);
    int x = json_object_get_int(x_obj);
    int y = json_object_get_int(y_obj);
    
    // 3. Determinar acción
    int action = 0;
    if (strcmp(action_str, "move") == 0) {
        action = MOUSE_MOVE;  // 0
    } else if (strcmp(action_str, "click_left") == 0) {
        action = MOUSE_CLICK_LEFT;  // 1
    } else if (strcmp(action_str, "click_right") == 0) {
        action = MOUSE_CLICK_RIGHT;  // 2
    }
    
    // 4. Ejecutar syscall
    if (mouse_control(action, x, y) == 0) {
        json_object_object_add(response, "success", 
                              json_object_new_boolean(1));
    } else {
        json_object_object_add(response, "success", 
                              json_object_new_boolean(0));
    }
    
    json_object_put(request);
    return send_json_response(connection, 200, response);
}
```

**Wrapper de Syscall**:
```c
int mouse_control(int action, int x, int y) {
    // action: 0=move, 1=click_left, 2=click_right
    // x, y: coordenadas absolutas normalizadas (0-32767)
    
    long result = syscall(SYS_MOVE_MOUSE, action, x, y);  // 555
    if (result < 0) {
        perror("syscall move_mouse");
        return -1;
    }
    return 0;
}
```

---

### 5. POST /api/remote/keyboard

**Descripción**: Envía eventos de teclado al sistema

**Request**:
```json
{
  "keycode": 30,
  "pressed": true
}
```

**Response**:
```json
{
  "success": true
}
```

**Código del Handler**:
```c
static enum MHD_Result handle_keyboard(struct MHD_Connection *connection,
                                      const char *token,
                                      struct connection_info *con_info) {
    json_object *response = json_object_new_object();
    
    // 1. Validar sesión y permisos
    if (!validate_session(token)) {
        return send_json_response(connection, 401, error);
    }
    
    session_t *session = get_session(token);
    if (!session->has_control_permission) {
        return send_json_response(connection, 403, error);
    }
    
    // 2. Parsear JSON
    json_object *request = json_tokener_parse(con_info->data);
    json_object *keycode_obj, *pressed_obj;
    json_object_object_get_ex(request, "keycode", &keycode_obj);
    json_object_object_get_ex(request, "pressed", &pressed_obj);
    
    int keycode = json_object_get_int(keycode_obj);
    int pressed = json_object_get_boolean(pressed_obj);
    
    printf("[keyboard] keycode=%d, pressed=%d\n", keycode, pressed);
    
    // 3. Ejecutar syscall
    if (keyboard_control(keycode, pressed) == 0) {
        json_object_object_add(response, "success", 
                              json_object_new_boolean(1));
    } else {
        json_object_object_add(response, "success", 
                              json_object_new_boolean(0));
    }
    
    json_object_put(request);
    return send_json_response(connection, 200, response);
}
```

**Wrapper de Syscall**:
```c
int keyboard_control(int keycode, int pressed) {
    // keycode: código de tecla de Linux (ver input-event-codes.h)
    // pressed: 1=presionar, 0=soltar
    
    long result = syscall(SYS_SEND_KEY_EVENT, keycode, pressed);  // 556
    if (result < 0) {
        perror("syscall send_key_event");
        return -1;
    }
    return 0;
}
```

---

## 🔧 Manejo de Datos POST

### Problema de libmicrohttpd

libmicrohttpd llama al handler **3 veces** para métodos POST:

1. **Primera llamada**: `*upload_data_size > 0`, `*con_cls == NULL`
   - Inicializar buffer
   - Retornar MHD_YES

2. **Segunda llamada**: `*upload_data_size > 0`, `*con_cls != NULL`
   - Acumular datos en buffer
   - Retornar MHD_YES

3. **Tercera llamada**: `*upload_data_size == 0`
   - Procesar datos completos
   - Retornar respuesta

### Estructura de Connection Info

```c
struct connection_info {
    char *data;      // Buffer de datos acumulados
    size_t size;     // Tamaño actual del buffer
};
```

### Código de Manejo POST

```c
static enum MHD_Result answer_to_connection(void *cls, 
                                           struct MHD_Connection *connection,
                                           const char *url, 
                                           const char *method,
                                           const char *version, 
                                           const char *upload_data,
                                           size_t *upload_data_size, 
                                           void **con_cls) {
    
    if (strcmp(method, "POST") == 0) {
        struct connection_info *con_info = *con_cls;
        
        // FASE 1: Inicializar
        if (con_info == NULL) {
            con_info = malloc(sizeof(struct connection_info));
            con_info->data = NULL;
            con_info->size = 0;
            *con_cls = con_info;
            printf("→ POST inicializando\n");
            return MHD_YES;
        }
        
        // FASE 2: Acumular datos
        if (*upload_data_size > 0) {
            // Realocar buffer
            con_info->data = realloc(con_info->data, 
                                    con_info->size + *upload_data_size + 1);
            
            // Copiar datos
            memcpy(con_info->data + con_info->size, 
                   upload_data, 
                   *upload_data_size);
            
            con_info->size += *upload_data_size;
            con_info->data[con_info->size] = '\0';
            
            *upload_data_size = 0;  // Indicar que se procesaron
            printf("→ POST acumulando (%zu bytes)\n", con_info->size);
            return MHD_YES;
        }
        
        // FASE 3: Procesar
        printf("→ POST procesando\n");
        // Aquí se llama al handler correspondiente
    }
    
    // Routing...
}
```

### Limpieza de Recursos

```c
static void request_completed_callback(void *cls, 
                                      struct MHD_Connection *connection,
                                      void **con_cls, 
                                      enum MHD_RequestTerminationCode toe) {
    struct connection_info *con_info = *con_cls;
    
    if (con_info != NULL) {
        if (con_info->data != NULL) {
            free(con_info->data);
        }
        free(con_info);
        *con_cls = NULL;
    }
}
```

---

## 🔒 Seguridad y Permisos

### Sistema de Permisos

```
┌──────────────────────────────────────┐
│        Grupos de Linux               │
├──────────────────────────────────────┤
│  remote_view                         │
│  ├─ Permiso: Ver pantalla            │
│  └─ Acceso: /api/remote/screen       │
│                                      │
│  remote_control                      │
│  ├─ Permiso: Control total           │
│  ├─ Acceso: /api/remote/mouse        │
│  └─ Acceso: /api/remote/keyboard     │
└──────────────────────────────────────┘
```

### Matriz de Permisos

| Endpoint | Sin Auth | View | Control |
|----------|----------|------|---------|
| POST /api/auth/login | ✅ | ✅ | ✅ |
| GET /api/monitor/stats | ❌ | ✅ | ✅ |
| GET /api/remote/screen | ❌ | ✅ | ✅ |
| POST /api/remote/mouse | ❌ | ❌ | ✅ |
| POST /api/remote/keyboard | ❌ | ❌ | ✅ |

### Flujo de Validación

```c
// 1. Extraer token del header
const char *token = get_token_from_headers(connection);

// 2. Validar sesión existe y no expiró
if (!validate_session(token)) {
    return send_json_response(connection, 401, "Sesión inválida");
}

// 3. Obtener sesión
session_t *session = get_session(token);

// 4. Verificar permiso específico
if (endpoint_requires_control && !session->has_control_permission) {
    return send_json_response(connection, 403, "Sin permisos de control");
}

// 5. Proceder con la operación
```

### Extracción de Token

```c
static const char* get_token_from_headers(struct MHD_Connection *connection) {
    const char *auth = MHD_lookup_connection_value(
        connection, 
        MHD_HEADER_KIND, 
        "Authorization"
    );
    
    if (auth == NULL) {
        return NULL;
    }
    
    // Verificar formato "Bearer <token>"
    if (strncmp(auth, "Bearer ", 7) == 0) {
        return auth + 7;  // Retornar solo el token
    }
    
    return NULL;
}
```

### CORS (Cross-Origin Resource Sharing)

```c
static enum MHD_Result send_json_response(struct MHD_Connection *connection,
                                         int status_code,
                                         json_object *json_obj) {
    const char *json_str = json_object_to_json_string(json_obj);
    
    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(json_str),
        (void*)json_str,
        MHD_RESPMEM_MUST_COPY
    );
    
    // Headers CORS
    MHD_add_response_header(response, "Content-Type", "application/json");
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(response, "Access-Control-Allow-Methods", 
                           "GET, POST, OPTIONS");
    MHD_add_response_header(response, "Access-Control-Allow-Headers", 
                           "Content-Type, Authorization");
    
    int ret = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);
    json_object_put(json_obj);
    
    return ret;
}
```

---

## 🚀 Compilación y Ejecución

### Makefile

```makefile
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11
LDFLAGS = -lmicrohttpd -lpam -ljson-c -luuid
TARGET = usaclinux_api
OBJS = main.o auth.o syscalls.o

all: $(TARGET)

$(TARGET): $(OBJS)
	@echo "🔨 Enlazando $(TARGET)..."
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)
	@echo "✅ Compilación exitosa!"

%.o: %.c
	@echo "📦 Compilando $<..."
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "🧹 Limpiando archivos..."
	rm -f $(OBJS) $(TARGET)
	@echo "✅ Limpieza completada"

.PHONY: all clean
```

### Ejecución

```bash
# Compilar
make clean && make

# Ejecutar (requiere sudo para syscalls)
sudo ./usaclinux_api

# Salida esperada:
# ✓ Servidor HTTP iniciado en puerto 8080
# ✓ Esperando conexiones...
```

### Logs del Backend

```
→ POST /api/auth/login (token: none) - inicializando
→ POST /api/auth/login (token: none) - acumulando (45 bytes)
→ POST /api/auth/login (token: none) - procesando
✓ Usuario autenticado: joshi (view=1, control=1)

→ GET /api/monitor/stats (token: present)
→ GET /api/remote/screen (token: present)

→ POST /api/remote/mouse (token: present) - inicializando
→ POST /api/remote/mouse (token: present) - procesando
[keyboard] keycode=30, pressed=1

→ POST /api/remote/keyboard (token: present) - inicializando
→ POST /api/remote/keyboard (token: present) - procesando
[keyboard] keycode=30, pressed=0
```

---

## 📊 Diagrama de Flujo Completo

```
┌─────────────────────────────────────────────────────┐
│                 Cliente (Browser)                    │
└────────────────────┬────────────────────────────────┘
                     │
                     │ 1. POST /api/auth/login
                     │    {username, password}
                     ▼
┌─────────────────────────────────────────────────────┐
│              Backend (main.c)                        │
│  ┌──────────────────────────────────────────────┐  │
│  │  answer_to_connection()                      │  │
│  │  ├─ Fase 1: Inicializar connection_info      │  │
│  │  ├─ Fase 2: Acumular datos POST              │  │
│  │  └─ Fase 3: Procesar y routear               │  │
│  └──────────────────┬───────────────────────────┘  │
│                     │                                │
│                     ▼                                │
│  ┌──────────────────────────────────────────────┐  │
│  │  handle_login()                              │  │
│  │  ├─ json_tokener_parse()                     │  │
│  │  ├─ authenticate_user() → PAM                │  │
│  │  ├─ check_user_permissions()                 │  │
│  │  ├─ create_session() → UUID                  │  │
│  │  └─ send_json_response()                     │  │
│  └──────────────────┬───────────────────────────┘  │
└─────────────────────┼───────────────────────────────┘
                      │
                      │ Token: "550e8400-..."
                      ▼
┌─────────────────────────────────────────────────────┐
│                 Cliente (Browser)                    │
│  Almacena token en memoria                          │
└────────────────────┬────────────────────────────────┘
                     │
                     │ 2. GET /api/remote/screen
                     │    Authorization: Bearer <token>
                     ▼
┌─────────────────────────────────────────────────────┐
│              Backend (main.c)                        │
│  ┌──────────────────────────────────────────────┐  │
│  │  handle_screen()                             │  │
│  │  ├─ validate_session(token)                  │  │
│  │  ├─ capture_screen() → syscall(550)          │  │
│  │  ├─ create_bmp()                             │  │
│  │  └─ MHD_queue_response()                     │  │
│  └──────────────────┬───────────────────────────┘  │
└─────────────────────┼───────────────────────────────┘
                      │
                      │ syscall(550, buffer)
                      ▼
┌─────────────────────────────────────────────────────┐
│            Kernel (sys_capture_screen)               │
│  ├─ Captura framebuffer                             │
│  ├─ Retorna metadata + píxeles RGB                  │
│  └─ En struct cap_buffer                            │
└─────────────────────┬───────────────────────────────┘
                      │
                      │ Datos de captura
                      ▼
┌─────────────────────────────────────────────────────┐
│              Backend (main.c)                        │
│  ┌──────────────────────────────────────────────┐  │
│  │  create_bmp()                                │  │
│  │  ├─ Crear BMP header (14 bytes)              │  │
│  │  ├─ Crear info header (40 bytes)             │  │
│  │  ├─ Convertir RGBA → BGR                     │  │
│  │  ├─ Invertir Y (BMP bottom-up)               │  │
│  │  └─ Agregar padding                          │  │
│  └──────────────────┬───────────────────────────┘  │
└─────────────────────┼───────────────────────────────┘
                      │
                      │ BMP completo
                      ▼
┌─────────────────────────────────────────────────────┐
│                 Cliente (Browser)                    │
│  Muestra imagen en <canvas>                         │
└─────────────────────────────────────────────────────┘
```

---

## 🎯 Resumen de Funcionalidades

### ✅ Autenticación
- Integración con PAM
- Validación de usuarios del sistema
- Verificación de grupos Linux
- Generación de tokens UUID
- Sesiones con timeout de 1 hora

### ✅ Monitoreo
- Estadísticas de CPU en tiempo real
- Estadísticas de RAM en tiempo real
- Timestamps para sincronización

### ✅ Control Remoto
- Captura de pantalla (BMP)
- Control de mouse (movimiento y clicks)
- Control de teclado (presionar/soltar teclas)
- Conversión de keycodes JavaScript → Linux

### ✅ Seguridad
- Autenticación obligatoria
- Sistema de permisos granular
- Validación de sesiones
- Timeout automático
- CORS configurado

### ✅ Arquitectura
- Servidor HTTP embebido
- Manejo de múltiples conexiones
- Buffering correcto de POST
- Integración directa con kernel
- Logging detallado

---

## 🐛 Depuración

### Logs Útiles

```bash
# Backend logs (stdout)
sudo ./usaclinux_api

# Kernel logs (syscalls)
dmesg | grep -E "(sys_move_mouse|sys_send_key_event|sys_capture_screen)"

# Probar syscalls manualmente
strace -e trace=syscall ./test_program
```

### Códigos de Error HTTP

- **200 OK**: Operación exitosa
- **400 Bad Request**: JSON inválido o faltan parámetros
- **401 Unauthorized**: Sesión inválida o expirada
- **403 Forbidden**: Sin permisos para la operación
- **404 Not Found**: Endpoint no existe
- **500 Internal Server Error**: Error en syscall o servidor

---

**Última actualización**: 22 de octubre de 2025
**Versión del Backend**: 1.0
**Autor**: Documentación técnica completa del backend USACLinux

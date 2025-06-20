# Tarea 3 - G-Root

# Guía Completa: Cómo Ejecutar el Rootkit

## Tabla de Contenidos
1. [Requisitos Previos](#requisitos-previos)
2. [Preparación del Entorno](#preparación-del-entorno)
3. [Compilación](#compilación)
4. [Instalación y Carga](#instalación-y-carga)
5. [Uso del Rootkit](#uso-del-rootkit)
6. [Ejemplos Prácticos](#ejemplos-prácticos)
7. [Solución de Problemas](#solución-de-problemas)
8. [Desinstalación](#desinstalación)

---

## 🛠Requisitos Previos

### Sistema Operativo
- **Linux** (Ubuntu 16.04.7 LTS)
 **Kernel 4.4+** (verificar con `uname -r`)
- **Permisos de administrador** (sudo)

### Herramientas Necesarias
```bash
# Instalar herramientas de desarrollo
sudo apt update
sudo apt install build-essential linux-headers-$(uname -r) gcc make

# En CentOS/RHEL:
# sudo yum groupinstall "Development Tools"
# sudo yum install kernel-devel kernel-headers
```

### Verificar Kernel
```bash
# Verificar versión del kernel
uname -r

# Verificar headers del kernel
ls /lib/modules/$(uname -r)/build || echo "❌ Headers no instalados"
```

---

## Preparación del Entorno

### 1. Crear Directorio de Trabajo
```bash
# Crear y entrar al directorio
mkdir ~/rootkit-proyecto
cd ~/rootkit-proyecto
```

### 2. Preparar Archivos del Proyecto
Necesitas estos archivos en tu directorio:
- `rootkit.c`
- `client.c`
- `config.h`
- `Makefile`

### 3. Estructura del Proyecto
```
tarea3-i2025/
├── rootkit.c          # Código del módulo del kernel
├── client.c           # Cliente para controlar el rootkit
├── config.h           # Configuraciones y comandos
├── Makefile           # Script de compilación
└── README.md          # Esta guía
```

---

## Compilación

### 1. Limpiar Compilaciones Anteriores
```bash
# Limpiar archivos compilados previos
make clean

# O manualmente:
rm -f *.o *.ko *.mod.c .*.cmd client
rm -rf .tmp_versions/
rm -f Module.symvers modules.order
```

### 2. Compilar el Proyecto
```bash
# Compilar todo (módulo + cliente)
make
make all
make client
```

### 3. Verificar Compilación
```bash
# Verificar archivos generados
ls -la *.ko          # Debería mostrar rootkit.ko
ls -la client        # Debería mostrar el ejecutable client
```

---

## Instalación y Carga

### 1. Cargar el Módulo del Kernel
```bash
# Cargar el rootkit en el kernel
sudo insmod rootkit.ko
```

### 2. Verificar Carga Exitosa
```bash
# Verificar que el módulo está cargado
lsmod | grep rootkit

# Ver logs de carga
dmesg | tail -10
```

### 3. Verificar Comunicación
```bash
# Probar que el cliente funciona
./client --help

```

---

## 🎮 Uso del Rootkit

### Comandos Disponibles

#### Control de Acceso
```bash
# Obtener shell root
./client --root-shell
```

#### Manejo de Archivos
```bash
# Ocultar archivo
./client --hide-file=archivo.txt

# Desocultar archivo  
./client --unhide-file=archivo.txt
```

#### Manejo de Directorios
```bash
# Ocultar directorio
./client --hide-dir=directorio_secreto

# Desocultar directorio
./client --unhide-dir=directorio_secreto
```

#### Manejo de Procesos
```bash
# Ocultar proceso (usar PID real)
./client --hide-pid=1234

# Desocultar proceso
./client --unhide-pid=1234
```

#### Manejo de Módulos
```bash
# Ocultar módulo del kernel
./client --hide-module=bluetooth

# Desocultar módulo
./client --unhide-module=bluetooth
```

#### Manejo de Conexiones
```bash
# Ocultar conexión por puerto
./client --hide-connection=4444

# Desocultar conexión
./client --unhide-connection=4444
```

#### Control del Rootkit
```bash
# Ocultar el rootkit mismo
./client --hide

# Desocultar el rootkit
./client --unhide

# Proteger de desinstalación
./client --protect

# Desproteger
./client --unprotect
```

---

## Ejemplos Prácticos

### Ejemplo 1: Ocultar un Archivo
```bash
# 1. Crear archivo de prueba
echo "contenido secreto" > /tmp/archivo_secreto.txt

# 2. Verificar que existe
ls /tmp/archivo_secreto.txt

# 3. Ocultar el archivo
./client --hide-file=archivo_secreto.txt

# 4. Verificar que está oculto
ls /tmp/ | grep archivo_secreto  # No debería aparecer
ls /tmp/ | grep Oculto          # Podría aparecer como "Oculto"

# 5. El archivo sigue accesible directamente
cat /tmp/archivo_secreto.txt    # Funciona

# 6. Desocultar
./client --unhide-file=archivo_secreto.txt
ls /tmp/archivo_secreto.txt     # Vuelve a aparecer
```

### Ejemplo 2: Ocultar un Proceso
```bash
# 1. Iniciar proceso en background
sleep 300 &
PID=$!
echo "PID del proceso: $PID"

# 2. Verificar que está visible
ps aux | grep $PID

# 3. Ocultar el proceso
./client --hide-pid=$PID

# 4. Verificar ocultamiento
ls /proc/ | grep $PID          # No debería aparecer
ls /proc/ | grep Oculto       # Podría aparecer como "Oculto"

# 5. El proceso sigue ejecutándose
kill -0 $PID && echo "Proceso aún activo"

# 6. Desocultar y limpiar
./client --unhide-pid=$PID
kill $PID
```

### Ejemplo 3: Ocultar Conexión de Red
```bash
# 1. Crear servidor en puerto específico
nc -l 7777 &
NC_PID=$!

# 2. Verificar conexión
netstat -tuln | grep 7777

# 3. Ocultar la conexión
./client --hide-connection=7777

# 4. Verificar ocultamiento
netstat -tuln | grep 7777     # No debería aparecer
cat /proc/net/tcp | grep Oculto  # Podría mostrar "Oculto"

# 5. La conexión sigue funcionando
# En otra terminal: echo "test" | nc localhost 7777

# 6. Limpiar
./client --unhide-connection=7777
kill $NC_PID
```

---

## Solución de Problemas

### Problema: "Permission denied"
```bash
# Solución: Usar sudo
sudo insmod rootkit.ko
sudo ./client --root-shell
```

### Problema: "Module not found"
```bash
# Verificar compilación
ls -la *.ko
make clean && make

# Verificar permisos
chmod +x client
```

### Problema: "Module rootkit is in use"
```bash
# Desproteger primero
./client --unprotect
./client --unhide

# Luego remover
sudo rmmod rootkit

# Si no funciona, reiniciar sistema
sudo reboot
```

### Problema: Cliente no responde
```bash
# Verificar que el módulo está cargado
lsmod | grep rootkit

# Verificar logs
dmesg | tail -20 | grep rootkit

# Verificar archivo de comunicación
ls -la /proc/version
```

### Problema: "No such file or directory" para headers
```bash
# Instalar headers del kernel
sudo apt install linux-headers-$(uname -r)

# Verificar instalación
ls /lib/modules/$(uname -r)/build
```

---

## Monitoreo y Logs

### Ver Actividad del Rootkit
```bash
# Logs en tiempo real
dmesg -w | grep rootkit

# Logs recientes
dmesg | tail -20 | grep rootkit

# Logs del sistema
journalctl -f | grep rootkit
```

### Verificar Estado
```bash
# Estado del módulo
lsmod | grep rootkit

# Procesos del cliente
ps aux | grep client

# Archivos del sistema
ls -la /proc/version
ls -la /sys/module/rootkit/
```

---

## Desinstalación

### Desinstalación Completa
```bash
# 1. Desproteger el rootkit
./client --unprotect

# 2. Desocultar el rootkit
./client --unhide

# 3. Limpiar elementos ocultos (opcional)
./client --unhide-file=archivo_secreto.txt
./client --unhide-pid=1234
./client --unhide-connection=4444

# 4. Remover el módulo
sudo rmmod rootkit

# 5. Verificar remoción
lsmod | grep rootkit  # No debería mostrar nada

# 6. Limpiar archivos compilados
make clean
rm -f client
```

### Desinstalación Forzada
```bash
# Si la desinstalación normal falla
sudo rmmod -f rootkit

# O reiniciar el sistema
sudo reboot
```

---

## Scripts de Automatización

### Script de Instalación Rápida
```bash
#!/bin/bash
echo "Instalando rootkit..."
make clean
make
sudo insmod rootkit.ko
echo "Rootkit instalado"
./client --help
```

### Script de Prueba Completa
```bash
#!/bin/bash
echo "Ejecutando pruebas del rootkit..."

# Prueba de archivos
echo "test" > /tmp/test_file.txt
./client --hide-file=test_file.txt
ls /tmp/ | grep -E "(test_file|Oculto)"
./client --unhide-file=test_file.txt
rm /tmp/test_file.txt

echo "Pruebas completadas"
```

---

## Advertencias Importantes

1. **Solo para Educación**: Este rootkit es solo para propósitos educativos
2. **Sistema Propio**: Solo usar en sistemas propios o con autorización
3. **Respaldo**: Hacer respaldo del sistema antes de usar
4. **Kernel Panic**: El código incorrecto puede causar kernel panic
5. **Detección**: Algunos antivirus pueden detectar el rootkit

# Tarea 3: G-Root

**Maestría en Ciberseguridad**

**Principios de Seguridad en Sistemas Operativos**

**Profesor.**
* Kevin Moraga

**Integrantes**
* Roberto Cordoba - 2025800352
* Daniel Araya - 2020207809
* Andrés Mora - 2013241401

## 1. Introducción: Presentar el problema

En el ámbito de la seguridad informática, los rootkits representan una de las amenazas más sofisticadas y peligrosas para los sistemas operativos modernos. Un rootkit es un tipo de software malicioso que otorga acceso privilegiado a un atacante y, al mismo tiempo, oculta su presencia del usuario legítimo y de las herramientas de monitoreo del sistema [1].

En particular, los rootkits que operan a nivel de kernel son los más complejos y potentes, ya que se ejecutan con los máximos privilegios del sistema operativo. Esto les permite interceptar llamadas del sistema, ocultar archivos, procesos, conexiones de red, módulos del kernel e incluso registrar las teclas pulsadas por el usuario (keylogging) [2]. El desarrollo de un rootkit de este tipo implica una comprensión profunda de los mecanismos internos del sistema operativo, como el manejo de módulos del kernel y la manipulación de estructuras de datos del sistema [3].

El objetivo de esta asignación es introducir al estudiante en el desarrollo de rootkits a nivel de kernel, a través de la modificación de un rootkit existente. La modificación consiste en intervenir el módulo de ocultamiento de archivos, de modo que en lugar de ocultar completamente un archivo del sistema, este se muestre con el nombre **"Oculto"**. Esto implica interceptar y alterar el comportamiento de las funciones internas del sistema que listan archivos, lo cual ofrece una valiosa oportunidad para entender cómo los rootkits logran evadir la detección [4].

Mediante esta tarea, se busca que el estudiante no solo ponga en práctica conceptos de bajo nivel del sistema operativo, sino que también desarrolle una conciencia crítica sobre los mecanismos de ataque utilizados por actores maliciosos, y cómo estos pueden comprometer la integridad, confidencialidad y disponibilidad de los sistemas.


## 2. Instrucciones para ejecutar el programa
### Configuración del entorno

El repositorio del proyecto puede ser clonado desde el siguiente enlace:  [G-Root](https://github.com/cuechin/tarea3-i2025.git)

Para el entorno del escenario se utilizan las siguientes sistemas operativos en la máquina virtual VMware Workstation Pro 17, aquí los siguientes enlaces para descargar el .iso:
* #### Target OS
  * [Ubuntu 16.04.7 LTS](https://releases.ubuntu.com/16.04/)
* #### Kernel
  * [4.4.0-22-generic](https://launchpad.net/ubuntu/+source/linux/4.4.0-22.40)

Para poder ejevutar el rootkit modificado en esta tarea, se preparó un entorno controlado en Linux. A continuación se describen los pasos ejecutados:

#### Archivos necesarios

Ubicar en el mismo directorio los siguientes archivos:

```
tarea3-i2025/
├── rootkit.c          # Código del módulo del kernel
├── client.c           # Cliente para controlar el rootkit
├── config.h           # Configuraciones y comandos
└── Makefile           # Script de compilación
```

### Compilación

#### 1. Limpiar Compilaciones Anteriores
```bash
# Limpiar archivos compilados previos
make clean

# O manualmente:
rm -f *.o *.ko *.mod.c .*.cmd client
rm -rf .tmp_versions/
rm -f Module.symvers modules.order
```

#### 2. Compilar el Proyecto
```bash
# Compilar todo (módulo + cliente)
make
make all
make client
```

#### 3. Verificar Compilación
```bash
# Verificar archivos generados
ls -la *.ko          # Debería mostrar rootkit.ko
ls -la client        # Debería mostrar el ejecutable client
```

---

### Instalación y Carga

#### 1. Cargar el Módulo del Kernel
```bash
# Cargar el rootkit en el kernel
sudo insmod rootkit.ko
```

#### 2. Verificar Carga Exitosa
```bash
# Verificar que el módulo está cargado
lsmod | grep rootkit

# Ver logs de carga
dmesg | tail -10
```

#### 3. Verificar Comunicación
```bash
# Probar que el cliente funciona
./client --help

```

---

### Uso del Rootkit

#### Comandos Disponibles

##### Control de Acceso
```bash
# Obtener shell root
./client --root-shell
```

##### Manejo de Archivos
```bash
# Ocultar archivo
./client --hide-file=archivo.txt

# Desocultar archivo  
./client --unhide-file=archivo.txt
```

##### Manejo de Directorios
```bash
# Ocultar directorio
./client --hide-dir=directorio_secreto

# Desocultar directorio
./client --unhide-dir=directorio_secreto
```

##### Manejo de Procesos
```bash
# Ocultar proceso (usar PID real)
./client --hide-pid=1234

# Desocultar proceso
./client --unhide-pid=1234
```

##### Manejo de Módulos
```bash
# Ocultar módulo del kernel
./client --hide-module=bluetooth

# Desocultar módulo
./client --unhide-module=bluetooth
```

##### Manejo de Conexiones
```bash
# Ocultar conexión por puerto
./client --hide-connection=4444

# Desocultar conexión
./client --unhide-connection=4444
```

##### Control del Rootkit
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

### Ejemplos Prácticos

#### Ejemplo 1: Ocultar un Archivo
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

#### Ejemplo 2: Ocultar un Proceso
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

#### Ejemplo 3: Ocultar Conexión de Red
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

### Solución de Problemas

#### Problema: "Permission denied"
```bash
# Solución: Usar sudo
sudo insmod rootkit.ko
sudo ./client --root-shell
```

#### Problema: "Module not found"
```bash
# Verificar compilación
ls -la *.ko
make clean && make

# Verificar permisos
chmod +x client
```

#### Problema: "Module rootkit is in use"
```bash
# Desproteger primero
./client --unprotect
./client --unhide

# Luego remover
sudo rmmod rootkit

# Si no funciona, reiniciar sistema
sudo reboot
```

#### Problema: Cliente no responde
```bash
# Verificar que el módulo está cargado
lsmod | grep rootkit

# Verificar logs
dmesg | tail -20 | grep rootkit

# Verificar archivo de comunicación
ls -la /proc/version
```

#### Problema: "No such file or directory" para headers
```bash
# Instalar headers del kernel
sudo apt install linux-headers-$(uname -r)

# Verificar instalación
ls /lib/modules/$(uname -r)/build
```

---

### Monitoreo y Logs

#### Ver Actividad del Rootkit
```bash
# Logs en tiempo real
dmesg -w | grep rootkit

# Logs recientes
dmesg | tail -20 | grep rootkit

# Logs del sistema
journalctl -f | grep rootkit
```

#### Verificar Estado
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

### Desinstalación

#### Desinstalación Completa
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

#### Desinstalación Forzada
```bash
# Si la desinstalación normal falla
sudo rmmod -f rootkit

# O reiniciar el sistema
sudo reboot
```

## 3. Descripción del Ataque

El ataque implementado en este proyecto se basa en la instalación de un **rootkit a nivel de kernel** en un sistema operativo Linux. Este tipo de rootkit opera con privilegios elevados (modo kernel), lo cual le permite interceptar y modificar directamente el comportamiento de funciones internas del sistema operativo, comprometiendo así su integridad, confidencialidad y disponibilidad [1].

En particular, este rootkit ha sido modificado para **no ocultar por completo ciertos elementos del sistema (archivos, procesos, conexiones, etc.)**, sino para hacerlos aparentar como si tuvieran el nombre `"Oculto"` dentro de las estructuras visibles del sistema. Este tipo de técnica busca confundir al administrador o usuario legítimo del sistema, ya que aunque técnicamente el archivo o proceso sigue estando visible, no se presenta con su nombre real, lo que puede dificultar su identificación y análisis [2].

### Técnicas utilizadas por el rootkit

Las principales técnicas de ocultamiento y manipulación empleadas incluyen:

- **Intercepción de llamadas al sistema (syscalls):** el rootkit reemplaza funciones como `readdir`, `getdents`, o equivalentes, para filtrar o modificar el contenido mostrado por comandos como `ls`, `ps`, `netstat`, etc. [3]
- **Manipulación de estructuras del kernel:** especialmente estructuras relacionadas con la lista de procesos (`task_struct`), módulos cargados (`module`) y directorios del sistema de archivos (`dentry`, `inode`).
- **Comunicación encubierta:** el rootkit responde a comandos específicos enviados por un cliente en espacio de usuario. Esta comunicación se da mediante una interfaz sencilla (syscall personalizada o escritura en `/proc`), y permite activar o desactivar el ocultamiento dinámicamente.
- **Persistencia en ejecución:** incluye mecanismos para ocultar el propio módulo (`rootkit.ko`) una vez cargado, así como impedir su desinstalación si se activa la protección [4].

### Justificación del ataque

El propósito del ataque es demostrar cómo, desde el nivel más bajo del sistema, un atacante puede alterar la percepción que tiene el usuario legítimo del estado del sistema operativo. Mostrar elementos con el nombre `"Oculto"` en lugar de eliminarlos completamente de la vista añade una capa de ambigüedad y engaño, alineada con las técnicas modernas de evasión y persistencia utilizadas en ataques reales [2]. Esto además permite observar la capacidad del kernel de seguir accediendo a los recursos, a pesar de su modificación aparente.

### Riesgos del ataque

Una vez instalado, el rootkit otorga control total al atacante, incluyendo:

- Escalada de privilegios (obtención de shell root).
- Ocultamiento de evidencia (archivos, procesos, módulos, conexiones).
- Persistencia dentro del sistema operativo aún tras reinicios (si se automatiza la carga del módulo).
- Dificultad para detección mediante herramientas tradicionales de monitoreo [5].

Este ataque simula lo que en un entorno real podría ser parte de una campaña de persistencia posterior a una intrusión inicial, con el objetivo de mantener el control del sistema comprometido sin ser detectado.


## 4. Documentación del ataque

El ataque desarrollado en esta tarea consiste en la instalación y uso de un rootkit a nivel de kernel que permite modificar la manera en que el sistema operativo reporta archivos, procesos, módulos y conexiones. A diferencia de los rootkits tradicionales que simplemente ocultan estos elementos, este proyecto realiza una **modificación en la capa de presentación**, reemplazando sus nombres reales por el nombre `"Oculto"` para dificultar su identificación sin dejar de estar accesibles para el atacante.

### Carga y funcionamiento del módulo

Una vez compilado el módulo del kernel (`rootkit.ko`), se carga al sistema mediante `insmod`. Al hacerlo, el rootkit intercepta diversas funciones del sistema, como `readdir`, `getdents`, y estructuras como `task_struct` y `/proc`, dependiendo del tipo de recurso que se desea ocultar o renombrar.

El módulo también habilita una interfaz de comunicación con un cliente en espacio de usuario (`client`) que permite enviar comandos para ejecutar distintas acciones, como:

- Ocultar archivos y directorios.
- Ocultar procesos en ejecución.
- Ocultar módulos del kernel.
- Ocultar conexiones de red activas.
- Otorgar acceso root mediante una shell escalada.
- Proteger al rootkit de ser eliminado por `rmmod`.

Esta comunicación se logra típicamente a través de syscalls específicas o mecanismos de escritura a archivos virtuales como `/proc` o `/dev`, que son interceptados por el rootkit.

### Ejecución del ataque

Una vez cargado, el rootkit permanece residente en memoria y responde a los comandos enviados desde el cliente. Por ejemplo:

```bash
./client --hide-file=secreto.txt
```

## 5. Autoevaluación

### Estado final del programa

El programa funciona correctamente en un entorno de pruebas controlado (máquina virtual con Ubuntu 16.04.7 y kernel 4.4.0-22-generic). Se logró modificar exitosamente el comportamiento del rootkit original para que, en lugar de ocultar completamente archivos, procesos y conexiones, estos se muestren con el nombre `"Oculto"`. Además, se conservó el resto de funcionalidades originales del rootkit, como escalada de privilegios, ocultamiento de módulos y protección contra desinstalación.

### Problemas encontrados

- **Compatibilidad con versiones recientes del kernel:** El código base del rootkit está diseñado para versiones anteriores a Linux 5.x. Intentos de compilarlo en kernels más nuevos resultaron en errores de compatibilidad debido a cambios en las APIs del kernel.
- **Desincronización entre el cliente y el kernel:** En algunos momentos, si el cliente envía comandos en un orden incorrecto (por ejemplo, intentar desocultar un archivo que no estaba oculto), no se genera retroalimentación clara.
- **Inestabilidad ocasional del sistema:** Algunas pruebas de ocultamiento de procesos provocaron bloqueos momentáneos en el sistema si el PID objetivo ya no existía.

### Limitaciones

- El ataque no es persistente tras reiniciar el sistema, a menos que se configure una carga automática del módulo.
- La implementación depende de estructuras internas del kernel que pueden variar entre versiones, lo que hace que sea sensible a cambios del sistema.
- No se implementó una capa de cifrado o autenticación en la comunicación entre el cliente y el rootkit, lo cual puede ser un riesgo en escenarios reales.

### Calificación sugerida (según rúbrica)

| Criterio                        | Valor (%) | Autoevaluación |
|-------------------------------|-----------|----------------|
| Entregable 1: Rootkit         | 50%       | 50%            |
| Entregable 2: Video           | 25%       | 25%            |
| Documentación del Ataque      | 25%       | 25%            |
| Extra (opcional)              | 10%       | 0%             |
| **Total estimado**            | **100%**  | **100%**       |

### Justificación de la calificación

El rootkit fue modificado exitosamente, cumple con el objetivo propuesto y se documentó claramente el ataque. La funcionalidad fue verificada mediante pruebas prácticas incluidas en este informe. No se implementó el desafío opcional de compatibilidad con kernel >5.0, ni la funcionalidad de shell reverso, por lo que no se reclama el porcentaje extra.


## 6. Lecciones Aprendidas

Desarrollar este proyecto nos permitió adentrarnos en una de las áreas más críticas y técnicas de la ciberseguridad: la manipulación del kernel de un sistema operativo. A continuación, se detallan algunas de las principales lecciones aprendidas durante el proceso:

### 1. Comprensión del espacio de kernel vs espacio de usuario

Trabajar con módulos de kernel evidenció las claras diferencias entre el espacio de usuario y el espacio de kernel. Modificar funciones del kernel implica una gran responsabilidad, ya que cualquier error puede comprometer la estabilidad total del sistema. Se reforzó el concepto de que los errores en este nivel no suelen generar mensajes claros ni logs accesibles, y pueden llevar a reinicios forzosos o corrupción del entorno.

### 2. Importancia de entornos controlados para pruebas

El uso de una máquina virtual fue indispensable. Las pruebas de rootkits nunca deben realizarse en un sistema operativo principal. La virtualización permite controlar, restaurar y observar los efectos del rootkit de forma segura y repetible. Además, aprendimos a preparar snapshots frecuentes para evitar pérdida de progreso ante fallos críticos.

### 3. Manipulación de estructuras internas del sistema

Entender y modificar estructuras como `task_struct`, `file_operations`, y el sistema de archivos virtual (`/proc`) nos ayudó a comprender cómo el sistema operativo representa y organiza recursos como procesos, módulos y archivos. Esta experiencia fue clave para comprender cómo los rootkits alteran la realidad percibida por el usuario y las herramientas de análisis.

### 4. Comunicación encubierta y control remoto

Aprendimos cómo un rootkit puede crear una interfaz de comunicación simple pero efectiva entre el kernel y el espacio de usuario. Esto permite enviar comandos específicos para ejecutar acciones críticas, como ocultar elementos del sistema o escalar privilegios, sin dejar trazas obvias.

### 5. Ética y responsabilidad

El desarrollo de herramientas ofensivas como rootkits exige una gran responsabilidad ética. Este proyecto se realizó con fines puramente académicos y nos ayudó a entender cómo los atacantes pueden abusar del control a bajo nivel para comprometer sistemas. Esta experiencia refuerza nuestro compromiso con la ciberseguridad defensiva y el uso responsable del conocimiento adquirido.


Estas lecciones consolidan no solo habilidades técnicas avanzadas, sino también una visión crítica sobre la seguridad del sistema operativo, que resulta esencial para cualquier profesional en formación dentro del área de ciberseguridad.


## 7. Video

## 8. Bibliografía


[1] Xcellerator, *Linux Rootkits Part 1: Introduction to Kernel Hacking*. Disponible en:  
[https://xcellerator.github.io/posts/linux_rootkits_01/](https://xcellerator.github.io/posts/linux_rootkits_01/)

[2] dsmatter, *bROOTus Rootkit Writeup*. Disponible en:  
[https://github.com/dsmatter/brootus/raw/master/docs/bROOTus_writeup.pdf](https://github.com/dsmatter/brootus/raw/master/docs/bROOTus_writeup.pdf)

[3] Jeena Sebastian, *Operating System Presentation: Rootkits*. Disponible en:  
[https://people.cse.nitc.ac.in/jeena/files/presentation_os_0.pdf](https://people.cse.nitc.ac.in/jeena/files/presentation_os_0.pdf)

[4] nurupo, *Linux Rootkit (GitHub Repository)*. Disponible en:  
[https://github.com/nurupo/rootkit](https://github.com/nurupo/rootkit)

[5] Phrack Magazine, *article 59-0x07: Kernel Rootkit Techniques*. Disponible en:  
[http://phrack.org/issues/59/7.html](http://phrack.org/issues/59/7.html)

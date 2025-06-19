#!/bin/bash

# Script de demostración del rootkit modificado
# Tarea 3 - Maestría en Ciberseguridad

echo "========================================="
echo "DEMOSTRACIÓN ROOTKIT MODIFICADO - TAREA 3"
echo "========================================="

# Función para mostrar pasos
show_step() {
    echo ""
    echo ">>> $1"
    echo "----------------------------------------"
}

# Verificar si somos root
if [ "$EUID" -ne 0 ]; then
    echo "Este script debe ejecutarse como root"
    exit 1
fi

show_step "1. Compilando el rootkit modificado"
make clean
make all

if [ ! -f "rootkit.ko" ]; then
    echo "Error: No se pudo compilar el módulo"
    exit 1
fi

show_step "2. Compilando el cliente"
make client

show_step "3. Creando archivos de prueba"
touch /tmp/archivo_normal.txt
touch /tmp/archivo_secreto.txt
echo "Archivo normal creado" > /tmp/archivo_normal.txt
echo "Archivo que será 'oculto'" > /tmp/archivo_secreto.txt

show_step "4. Listando archivos antes de cargar el rootkit"
echo "Archivos en /tmp antes:"
ls -la /tmp/ | grep archivo_

show_step "5. Cargando el rootkit modificado"
insmod rootkit.ko

show_step "6. Verificando que el módulo se cargó"
lsmod | grep rootkit

show_step "7. Agregando archivo a la lista de 'ocultos'"
echo "Ocultando archivo_secreto.txt (se mostrará como 'Oculto')"
./client --hide-file=archivo_secreto.txt

show_step "8. Listando archivos después de 'ocultar'"
echo "Archivos en /tmp después (debería aparecer 'Oculto'):"
ls -la /tmp/ | grep -E "(archivo_|Oculto)"

show_step "9. Verificando logs del kernel"
echo "Últimos logs del rootkit:"
dmesg | tail -10 | grep -i rootkit

show_step "10. Creando un proceso para ocultar"
sleep 300 &
PID_SLEEP=$!
echo "Proceso sleep creado con PID: $PID_SLEEP"

show_step "11. Ocultando el proceso (se mostrará como 'Oculto')"
./client --hide-pid=$PID_SLEEP

show_step "12. Verificando procesos en /proc"
echo "Buscando procesos 'Oculto' en /proc:"
ls /proc/ | grep -E "(^[0-9]+$|Oculto)" | tail -10

show_step "13. Desocultando el archivo"
./client --unhide-file=archivo_secreto.txt
echo "Archivo desocultado, verificando:"
ls -la /tmp/ | grep archivo_

show_step "14. Desocultando el proceso"
./client --unhide-pid=$PID_SLEEP
echo "Proceso desocultado"

show_step "15. Terminando proceso de prueba"
kill $PID_SLEEP 2>/dev/null

show_step "16. Removiendo el rootkit"
rmmod rootkit

show_step "17. Limpiando archivos de prueba"
rm -f /tmp/archivo_normal.txt /tmp/archivo_secreto.txt

show_step "18. Verificación final"
echo "Archivos en /tmp después de limpiar:"
ls -la /tmp/ | grep archivo_ || echo "Sin archivos de prueba (correcto)"

echo ""
echo "========================================="
echo "DEMOSTRACIÓN COMPLETADA"
echo "========================================="
echo "MODIFICACIÓN IMPLEMENTADA:"
echo "- Los archivos 'ocultos' ahora aparecen como 'Oculto'"
echo "- Los procesos 'ocultos' ahora aparecen como 'Oculto'"
echo "- El módulo del kernel aparece como 'Oculto' cuando está oculto"
echo "========================================="

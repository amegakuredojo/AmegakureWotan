#include <tunables/global>

profile karasu-strict-profile flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  
  # Permitir lectura de librerías y dependencias
  /usr/local/lib/python3.*/site-packages/** r,
  /usr/local/bin/** rx,
  
  # Acceso estricto al código de la aplicación (solo lectura)
  /app/src/** r,
  /app/skills/** r,
  /app/opsec/** r,
  
  # Acceso de escritura solo a data/ y tmp
  /data/** rw,
  /tmp/** rw,
  
  # Red y DNS
  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,
  
  # Prevenir escalada de privilegios y ejecución de shells interactivas
  deny /bin/sh x,
  deny /bin/bash x,
  deny /usr/bin/sudo x,
  deny /usr/bin/su x,
  
  # Prevenir debugging y lectura de memoria de otros procesos
  deny ptrace,
  deny capability sys_ptrace,
  
  # Permisos WORM simulados (prevenir eliminación de evidencias una vez escritas)
  # Esto complementa chattr
  audit deny /data/evidence/** d,
}

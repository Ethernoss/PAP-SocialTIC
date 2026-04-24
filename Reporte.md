# Pruebas de concepto (PoC) y Análisis de Cadenas de Explotación en Android: CVE-2020-16040 (V8 Type Confusion) y CVE-2021-0920 (Escalada de Privilegios en Kernel)

**Instituto Tecnológico y de Estudios Superiores de Occidente (ITESO)**  
Proyecto de Aplicación Profesional – PAP ITESO 2026  
Colaboración: SocialTIC

**Autor:** Jorge Francisco Arriaga Escamilla  
**Guadalajara, Jalisco – 2026**

---

## Índice

1. [Introducción](#1-introducción)
2. [Explicación](#2-explicación)
   - 2.1 [¿Qué es una cadena de explotación?](#21-qué-es-una-cadena-de-explotación)
   - 2.2 [Uso en escenarios reales](#22-uso-en-escenarios-reales)
3. [Reference – Referencia Técnica](#3-reference-referencia-técnica)
   - 3.1 [CVE-2020-16040: Type Confusion en el Motor V8 de Chromium](#31-cve-2020-16040-type-confusion-en-el-motor-v8-de-chromium)
   - 3.2 [CVE-2021-0920: Escalada de Privilegios en el Kernel Android](#32-cve-2021-0920-escalada-de-privilegios-en-el-kernel-android)
4. [Tutorial – Implementación del Proyecto](#4-tutorial-implementación-del-proyecto)
5. [How-To – Análisis Forense y Hallazgos](#5-how-to-análisis-forense-y-hallazgos)
6. [Conclusión](#6-conclusión)
7. [Referencias](#referencias)

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

V8 es el motor de JavaScript de código abierto de Google, usado en Chromium, responsable de parsear, compilar y ejecutar el código de las páginas web.  Implementa varios *pipelines*: Ignition (intérprete de *bytecode*) y dos compiladores JIT, Sparkplug y TurboFan. TurboFan, el más agresivo en optimización, genera código máquina de alto rendimiento usando una representación intermedia llamada «*sea of nodes*» y especulación de tipos.  Asume que los tipos de los objetos se mantienen estables, generando código optimizado que evita verificaciones de tipo.  Si el tipo cambia, el motor debe desoptimizar. La vulnerabilidad CVE-2020-16040 permitía que, bajo ciertas condiciones, esta desoptimización fallara, dejando a TurboFan operando con una representación de tipo incorrecta sobre un objeto cuyo tipo real había cambiado.


#### 3.1.2 Type Confusion


#### 3.1.3 De type confusion a AAR/AAW y RCE

---

### 3.2 CVE-2021-0920: Escalada de Privilegios en el Kernel Android

#### 3.2.1 Descripción del componente afectado

#### 3.2.2 Use-after-free y race-condition

#### 3.2.3 Primitiva de escalada de privilegios

#### 3.2.4 Relación con la cadena de explotación


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


#### 4.2.2 Implementación de AAR/AAW mediante ArrayBuffer sintético


#### 4.2.3 Integración de WebAssembly para ejecución de shellcode


### 4.3 Pruebas de ejecución y resultados observados

#### 4.3.1 Ejecución del exploit en el renderer

El *exploit* fue entregado al dispositivo objetivo a través de un servidor HTTP local en el *host* de análisis, accedido desde el navegador Chrome 72.0.3626.121 en el dispositivo Android. La página HTML de entrega contenía el *exploit* JavaScript completo e inicializaba automáticamente la secuencia de explotación al ser cargada. La ejecución fue monitoreada desde el *host* mediante `adb logcat` para capturar mensajes del sistema, y mediante Chrome DevTools Protocol para observar el estado del *renderer*.

En las primeras iteraciones, la ejecución produjo *crashes* del proceso del *renderer*, manifestados como señales `SIGSEGV` (violación de segmento) capturadas en los *tombstones* del sistema. Estos *crashes* iniciales fueron informativos: indicaban que el *exploit* llegaba a la fase de escritura en memoria pero con *offsets* incorrectos para la versión específica del binario de Chrome instalado en el dispositivo, lo que producía escrituras en regiones de memoria no mapeadas en lugar de en la región RWX objetivo.

#### 4.3.2 Ajuste de offsets y verificación

El proceso de ajuste de *offsets* requirió un ciclo iterativo de análisis. Para cada *crash*, el *tombstone* generado por Android fue extraído mediante ADB y analizado para determinar la dirección de fallo y el registro de retorno. Combinando esta información con el análisis del binario de Chrome extraído del dispositivo y los símbolos de depuración disponibles en el repositorio público de Chromium, fue posible identificar con precisión los *offsets* de los campos críticos del *layout* de objetos V8 en esa versión específica del binario ARM64.

Los *offsets* más relevantes para la estabilidad del *exploit* resultaron ser el del campo `backing_store` dentro del objeto `JSArrayBuffer` y el del campo `jump_table_start` dentro del objeto `NativeModule` de WebAssembly.

#### 4.3.3 Resultado: ejecución en el renderer y limitaciones del sandbox


### 4.4 Análisis de CVE-2021-0920 en contexto aislado


---

## 5. How-To: Análisis Forense y Hallazgos

Esta sección tiene propósito procedimental: describe cómo reproducir los pasos de análisis forense realizados en el proyecto, qué artefactos buscar en un dispositivo potencialmente comprometido, y cómo interpretar la evidencia recopilada. Está orientada a un lector técnico que desee aplicar estos procedimientos a sus propias investigaciones.

### 5.1 Configuración del entorno de análisis forense

#### 5.1.1 Requisitos previos

#### 5.1.2 Instalación de MVT

#### 5.1.3 Obtención de androidqf

### 5.2 Extracción de artefactos con androidqf

#### 5.2.1 Procedimiento de extracción

### 5.3 Análisis con MVT

#### 5.3.1 Análisis de la adquisición de androidqf

#### 5.3.2 Interpretación de la salida de MVT

### 5.4 Análisis de tombstones y logcat

#### 5.4.1 Estructura de un tombstone

#### 5.4.2 Patrones en logcat asociados a explotación del navegador

### 5.5 Evidencia obtenida y hallazgos del proyecto

---

## 6. Conclusión

---

## Referencias

Google Project Zero. (2020). *CVE-2020-16040 analysis: V8 type confusion in TurboFan*. Google Project Zero Blog. https://googleprojectzero.blogspot.com/

Google Project Zero. (2021). *CVE-2021-0920: Linux kernel unix_gc use-after-free*. Project Zero Issue Tracker. https://bugs.chromium.org/p/project-zero/


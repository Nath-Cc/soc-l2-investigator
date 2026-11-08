# SOC L2 Investigator

Aplicación web para investigar incidentes a partir de registros exportados en Excel. Proyecto académico de Comunidad Dojo y WoSEC Panamá.

## Contexto

Una consultora de ciberseguridad ubicada en Estocolmo recibe los registros de un cliente. La analista SOC Nivel 2 reconstruye la secuencia de eventos, documenta indicadores candidatos y propone verificaciones con respaldo en la evidencia.

## Inicio rápido

1. Guarda `index.html`, `styles.css` y `app.js` en la misma carpeta.
2. Abre `index.html` en Chrome o Edge.
3. Carga `SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx`.
4. Revisa el dashboard y expande un hallazgo para ver sus registros.
5. Descarga los informes ejecutivo y técnico.

Se requiere conexión a internet para cargar SheetJS y jsPDF desde el CDN. El Excel se analiza en el navegador. El tamaño máximo de carga es de 15 MB.

## Análisis y evidencia

- **Autenticación.** Cuatro o más fallos de inicio de sesión en los diez minutos anteriores a un acceso exitoso para la misma cuenta, IP, equipo y clasificación RDP.
- **Red.** Diez o más solicitudes HTTPS POST de un equipo al mismo destino dentro de la exportación.
- **Procesos.** Revisión de líneas de comandos que contienen herramientas o argumentos de interés.

Cada hallazgo muestra su severidad inicial, confianza y `Log_ID` asociados. Los indicadores son candidatos a investigación. La confirmación requiere validar el contexto y el alcance con el cliente.

## Revisión asistida con IA

1. Selecciona un hallazgo en **Consultar un hallazgo con IA**.
2. Copia el prompt y pégalo en ChatGPT.
3. Contrasta la respuesta con los registros y verifica los `Log_ID`.
4. Pega una nota revisada y marca la casilla para incluirla en los PDF.

La consulta es manual. La aplicación prepara el texto y la analista decide si lo comparte. Para la demostración, usa datos sintéticos. Si trabajas con registros de un cliente, verifica la autorización antes de compartirlos con un servicio externo.

## Entregables

- **Informe ejecutivo.** Alcance, hallazgos, referencias principales y acciones propuestas.
- **Informe técnico.** Metodología, cronología y registros asociados a cada hallazgo.
- **Video demo.** Carga del Excel, revisión de evidencia, consulta asistida y descarga de ambos informes.

## Validación del caso de laboratorio

Con el Excel del bootcamp, verifica que el dashboard muestre **715 eventos**. Abre **Fallos RDP seguidos de acceso exitoso** y comprueba que aparezcan cuatro fallos entre las 09:02 y las 09:05, seguidos del acceso exitoso `EVT-00188` a las 09:06.

## Estructura

| Archivo | Responsabilidad |
|---|---|
| `index.html` | Estructura e interfaz |
| `styles.css` | Diseño claro y adaptable |
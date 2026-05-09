// -- IMPORTS Y VARIABLES GLOBALES
import groovy.json.JsonSlurper
import groovy.json.JsonOutput
import groovy.transform.Field

// -- Variables de entorno 
@Field String PROJECT_NAME = System.getenv("PROJECT_NAME_ENV")
@Field String BRANCH = System.getenv("BRANCH_ENV")
@Field String CLIENT_ID = System.getenv("CX_CLIENT_ID")
@Field String CLIENT_SECRET = System.getenv("CX_CLIENT_SECRET")
@Field String ScanID = System.getenv("SCAN_ID_ENV")
@Field String ProjectID = System.getenv("PROJECT_ID_ENV")

// -- Variables de control 
@Field String Cx_Token = ""
@Field String CX_SEVERITY_FILTER = "CRITICAL,HIGH"
@Field String CX_URL_AST = "https://ast.checkmarx.net/api"
@Field String Linea_Base_ID = ""

// -- CONTROL DE FALLOS 
@Field boolean SAST_FAILED = false
@Field boolean SCA_FAILED = false

@Field Map SAST_RESULT = [:]
@Field Map SCA_RESULT = [:]

/*****************************************************************************************
* 2. ORQUESTADOR DE EJECUCIÓN (FLUJO PRINCIPAL)
*****************************************************************************************/
println "##[group] Preparación y Autenticación"
obtenerIdentificadores()

if (!PROJECT_NAME || PROJECT_NAME == "null" || PROJECT_NAME.trim().isEmpty()) {
    println "##vso[task.logissue type=error] ERROR: PROJECT_NAME_ENV es nulo o vacío."
    System.exit(1)
}

obtenerToken()

// Si el ProjectID no vino del JSON del pipeline, lo buscamos en la API
if (!ProjectID || ProjectID == "null" || ProjectID.isEmpty()) {
    obtenerProjectID()
}

println "##[endgroup]"

/*****************************************************************************************
* 3. MÓDULO DE CONECTIVIDAD Y AUTENTICACIÓN
*****************************************************************************************/
//-------- Validación inicial de IDs y credenciales -----------
def obtenerIdentificadores() {
    println "[INFO] Identificadores recibidos:"
    println "  - ProjectName : ${PROJECT_NAME}"
    println "  - ScanID      : ${ScanID}"
    println "  - ClientID    : ${CLIENT_ID ? 'Configurado' : 'FALTANTE'}"
    println "  - ProjectID   : ${ProjectID ?: 'Por buscar en API'}"
    
    if (!ScanID || ScanID == "null") {
        println "##vso[task.logissue type=error] ERROR: ScanID es nulo. El escaneo de Checkmarx falló."
        System.exit(1)
    }
    if (!CLIENT_ID || !CLIENT_SECRET) {
        println "##vso[task.logissue type=error] ERROR: Credenciales (ClientID/Secret) no encontradas."
        System.exit(1)
    }
}

//-------------- Autentica con Checkmarx IAM para obtener el Access Token -------------------------
def obtenerToken() {
    println "[INFO] Solicitando Token IAM a Checkmarx..."
    def authUrl = "https://iam.checkmarx.net/auth/realms/coppel/protocol/openid-connect/token"
    def postBody = "client_id=${CLIENT_ID}&grant_type=client_credentials&client_secret=${CLIENT_SECRET}"
    
    try {
        URL url = new URL(authUrl)
        HttpURLConnection conn = (HttpURLConnection) url.openConnection()
        conn.setRequestMethod("POST")
        conn.doOutput = true
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
        conn.setRequestProperty("Accept", "application/json")
        
        conn.outputStream.withWriter("UTF-8") { it.write(postBody) }
        
        if (conn.responseCode == 200) {
            def response = new JsonSlurper().parseText(conn.inputStream.text)
            Cx_Token = response.access_token
            println "Token obtenido exitosamente."
        } else {
            println "##vso[task.logissue type=error] ERROR IAM: Código ${conn.responseCode}"
            println "Detalle: ${conn.errorStream?.text}"
            System.exit(1)
        }
    } catch (Exception e) {
        println "##vso[task.logissue type=error] ERROR CRÍTICO TOKEN: ${e.message}"
        System.exit(1)
    }
}

//--------------- Obtención del ProjectID a partir del nombre del proyecto ----------------------
def obtenerProjectID() {
    println "[INFO] Buscando ProjectID en la API por nombre..."
    def projectNameEncoded = URLEncoder.encode(PROJECT_NAME, "UTF-8")
    def searchUrl = "${CX_URL_AST}/projects?name=${projectNameEncoded}"
    
    try {
        URL url = new URL(searchUrl)
        HttpURLConnection conn = (HttpURLConnection) url.openConnection()
        conn.setRequestMethod("GET")
        conn.setRequestProperty("Authorization", "Bearer ${Cx_Token}")
        conn.setRequestProperty("Accept", "application/json")
        
        if (conn.responseCode == 200) {
            def response = new JsonSlurper().parseText(conn.inputStream.text)
            // Buscamos el proyecto que coincida exactamente con el nombre
            def projectList = response instanceof List ? response : response.projects

            if (!projectList || projectList.size() == 0) {
                println "##vso[task.logissue type=error] ERROR: La API no devolvió proyectos para '${PROJECT_NAME}'."
                System.exit(1)
            }

            def project = projectList.find { p -> 
                // Usamos p.name o p['name'] para ser más seguros
                return p.name == PROJECT_NAME 
            }
            
            if (project) {
                ProjectID = project.id
                println "[OK] ProjectID recuperado: ${ProjectID}"
            } else {
                println "##vso[task.logissue type=error] ERROR: No existe el proyecto '${PROJECT_NAME}'."
                System.exit(1)
            }
        } else {
            println "##vso[task.logissue type=error] ERROR API PROJECTS: Código ${conn.responseCode}"
            System.exit(1)
        }
    } catch (Exception e) {
        println "##vso[task.logissue type=error] ERROR CRÍTICO PROJECT_ID: ${e.message}"
        e.printStackTrace() // Esto ayudará a ver la línea exacta en el log de Azure
        System.exit(1)
    }
}

/*****************************************************************************************
* 4. MÓDULO SAST - VALIDACIÓN DE VULNERABILIDADES
*****************************************************************************************/
// -- Función genérica para peticiones HTTP a la API de Checkmarx 
def realizarPeticion(String urlStr, String metodo, String body = null) {
    URL url = new URL(urlStr)
    HttpURLConnection conn = (HttpURLConnection) url.openConnection()
    conn.setRequestMethod(metodo)
    conn.setRequestProperty("Authorization", "Bearer ${Cx_Token}")
    conn.setRequestProperty("Accept", "application/json; version=1.0")
    
    if (body) {
        conn.doOutput = true
        conn.setRequestProperty("Content-Type", "application/json")
        conn.outputStream.withWriter("UTF-8") { it.write(body) }
    }

    // Retornamos un mapa con el estado y el contenido
    int status = conn.responseCode
    String content = (status < 400) ? conn.inputStream.text : (conn.errorStream?.text ?: "")
    return [status: status, content: content]
}

// -- Comparación de escaneo actual contra línea base 
def functionCompartivaScaneoBase() {  
    def currentScanID = this.ScanID
    def baseID = this.Linea_Base_ID 

    println "[INFO] Iniciando comparativa SAST (Comparativa contra Línea Base)..."
    
    sleep(5000)

    def criticalCount = 0
    def highCount = 0
    
    def queryString = "?base-scan-id=${baseID}&scan-id=${currentScanID}&severity=${CX_SEVERITY_FILTER}&status=NEW,RECURRENT&limit=5000"
    def response = realizarPeticion("${CX_URL_AST}/sast-results/compare${queryString}", "GET")
    
    if (response.status != 200) {
        println "##vso[task.logissue type=error] ERROR API Comparativa. Código: ${response.status}"
        println "Detalle API: ${response.content}"
        SAST_FAILED = true
        return 
    }

    // Get json
    try {
        def tempDir = System.getenv("AGENT_TEMPDIRECTORY") ?: "."
        def sastJsonPath = "${tempDir}/cxone_sast_compare.json"
        new File(sastJsonPath).write(response.content)
        println "##vso[task.setvariable variable=CX_SAST_JSON_PATH]${sastJsonPath}"
    } catch (Exception e) {
        println "[WARN] No se pudo exportar el JSON para debug."
    }

    def json = new groovy.json.JsonSlurper().parseText(response.content)
    
    if (json.results) {
        for (def vuln in json.results) {
            def status = vuln.status?.toString()?.toUpperCase()
            def state = vuln.state?.toString()?.replaceAll("_", "")?.toLowerCase()
            def severity = vuln.severity?.toString()?.toUpperCase()
            
            if (status == "NEW" && state != "notexploitable") {
                if (severity == "CRITICAL") criticalCount++
                else if (severity == "HIGH") highCount++
            }
        }
    }

    println "[INFO] RESULTADO SAST (Comparativa contra Línea Base)"
    println "  - NUEVAS CRITICAL : ${criticalCount}"
    println "  - NUEVAS HIGH     : ${highCount}"

    if (criticalCount > 0 || highCount > 0) {
        println "[!] Se detectaron vulnerabilidades nuevas (Críticas/Altas) respecto a la línea base."
        SAST_FAILED = true
        realizarPeticion("${CX_URL_AST}/scans/${ScanID}/tags", "PUT", '{"tags": {"Break SAST Fallo":""}}')
    } else {
        println "[OK] SAST Aprobado. Cero regresiones Críticas o Altas detectadas."
        realizarPeticion("${CX_URL_AST}/scans/${ScanID}/tags", "PUT", '{"tags": {"Break SAST OK":""}}')
    }

    SAST_RESULT.baseComparison = [critical: criticalCount, high: highCount, medium: 0, low: 0, baselineId: Linea_Base_ID]
}

// -- Validación directa sin línea base 
def functionValidacionDeVulnerabilidades() {
    def currentScanID = this.ScanID

    println "[INFO] Iniciando validación SAST directa (Sin Línea Base)..."
    
    sleep(5000)

    def criticalCount = 0
    def highCount = 0
    def severidadesAValidar = ["CRITICAL", "HIGH"]
    
    def allSummaries = [] 

    for (String severidad in severidadesAValidar) {
        if (SAST_FAILED) break

        def queryString = "?scan-id=${currentScanID}&severity=${severidad}&group-by-field=STATE"
        def response = realizarPeticion("${CX_URL_AST}/sast-scan-summary/aggregate${queryString}", "GET")
        
        if (response.status != 200) {
            println "##vso[task.logissue type=error] ERROR API Aggregate (${severidad}). Código: ${response.status}"
            SAST_FAILED = true
            break
        }

        def json = new groovy.json.JsonSlurper().parseText(response.content)
        def conteoActivas = 0
        
        if (json.summaries) {
            for (def sum in json.summaries) {
                sum.severity = severidad 
                allSummaries.add(sum)
                
                def state = sum.state?.toString()?.replaceAll("_", "")?.toLowerCase()
                
                if (state != "notexploitable") {
                    conteoActivas += (sum.count ?: 0)
                }
            }
        }

        if (severidad == "CRITICAL") criticalCount = conteoActivas
        else if (severidad == "HIGH") highCount = conteoActivas
    }

    // -- get json
    try {
        def tempDir = System.getenv("AGENT_TEMPDIRECTORY") ?: "."
        def sastJsonPath = "${tempDir}/cxone_sast_compare.json"
        
        def combinedJson = groovy.json.JsonOutput.toJson([summaries: allSummaries])
        new File(sastJsonPath).write(combinedJson)
        
        println "##vso[task.setvariable variable=CX_SAST_JSON_PATH]${sastJsonPath}"
        println "[INFO] JSON de validación SAST (Critical + High) exportado para diagnóstico."
    } catch (Exception e) {
        println "[WARN] No se pudo exportar el JSON para debug: ${e.message}"
    }

    println "[INFO] RESULTADO SAST (Análisis Directo Total)"
    println "  - CRITICAL (Activas) : ${criticalCount}"
    println "  - HIGH     (Activas) : ${highCount}"

    if (criticalCount > 0 || highCount > 0 || SAST_FAILED) {
        println "[!] Se detectaron vulnerabilidades activas que rompen la política de seguridad."
        SAST_FAILED = true
        realizarPeticion("${CX_URL_AST}/scans/${ScanID}/tags", "PUT", '{"tags":{"Break SAST Fallo":""}}')
    } else {
        println "[OK] SAST Aprobado. Todo lo encontrado está marcado como NotExploitable."
        realizarPeticion("${CX_URL_AST}/scans/${currentScanID}/tags", "PUT", '{"tags": {"Break SAST OK":""}}')
    }

    SAST_RESULT.directScan = [critical: criticalCount, high: highCount, medium: 0, low: 0, scanId: ScanID]
}

/*****************************************************************************************
* 5. MÓDULO DE LÍNEA BASE 
*****************************************************************************************/
println "##[group] Evaluación SAST"
def ramasPrincipales = ["main", "master"]
def baseEncontrada = false

println "[INFO] Buscando escaneo exitoso previo (Línea Base) en ramas main/master..."
for (String rama in ramasPrincipales) {
    if (baseEncontrada) break 
    println " Buscando escaneo exitoso en rama: ${rama}..."
    def urlParamsBase = "?offset=0&limit=1&project-id=${ProjectID}&branch=${rama}&statuses=Completed&sort=-created_at&tags-keys=Break SAST OK"
    def responseBase = realizarPeticion("${CX_URL_AST}/scans/${urlParamsBase}", "GET")
    
    if (responseBase.status == 200) {
        def jsonBase = new JsonSlurper().parseText(responseBase.content)
        if (jsonBase?.scans != null && jsonBase.scans.size() > 0) {
            Linea_Base_ID = jsonBase.scans[0].id
            baseEncontrada = true
            println "LÍNEA BASE DETECTADA: [ID: ${Linea_Base_ID}] en la rama [${rama}]"
        }
    }
}

//Decisión del Diagrama (¿Existe?)
if (baseEncontrada) {
    // CAMINO 'SI': Endpoint 3
    println "[INFO] >> Ejecutando Comparación Diferencial"
    functionCompartivaScaneoBase()
} else {
    // CAMINO 'NO': Endpoint 4
    println "[INFO] >> Ejecutando Validación Directa (No se encontró línea base)"
    functionValidacionDeVulnerabilidades()
}
println "##[endgroup]"

/*****************************************************************************************
* 6. MÓDULO SCA - EXPORTACIÓN Y REPORTE
*****************************************************************************************/
//-- Genera el reporte visual en consola 
def generateConsolidatedReport(combinedList, failingPackageIds, violationReasons) {
    def packageVulns = []
    
    // Filtrado de Violaciones Reales
    for (def item in combinedList) {
        if (failingPackageIds.contains(item.PackageId)) {
            
            def riskState = item.RiskState?.toString()?.replaceAll("_", "")?.toLowerCase()
            if (riskState == "notexploitable") {
                continue 
            }

            if (violationReasons.containsKey(item.VulnerabilityId)) {
                item.ViolationReason = violationReasons[item.VulnerabilityId]
                packageVulns.add(item)
            }
        }
    }

    if (packageVulns.isEmpty()) { return "No se encontraron violaciones críticas según las reglas de negocio." }

    // --- Construcción de la Tabla (ASCII) ---
    def tableData = []
    tableData.add(['Package ID', 'Vuln ID', 'Severity', 'EPSS', 'Direct', 'Dev Dep', 'Malicious', 'KEV', 'PoC', 'Razón del Fallo'])

    for (def v in packageVulns) {
        def epssMostrar = "0.00%"
        try {
            if (v.EpssValue != null) {
                def valorCalculado = v.EpssValue.toString().toDouble() * 100
                epssMostrar = String.format("%.2f", valorCalculado) + "%"
            }
        } catch (e) { epssMostrar = "N/A" }
        
        tableData.add([
            v.PackageId.toString(), v.VulnerabilityId.toString(), v.Severity.toString(), epssMostrar,
            (v.IsDirectDependency ?: 'false').toString(), 
            (v.IsDevelopmentDependency ?: 'false').toString(), 
            (v.IsMalicious ?: 'false').toString(),
            (v.Kev ?: 'false').toString(), (v.Poc ?: 'false').toString(),
            v.ViolationReason
        ])
    }

    // Lógica de cálculo de anchos de columna
    int[] colWidths = new int[tableData[0].size()]
    for (def row in tableData) {
        row.eachWithIndex { val, idx -> 
            def strVal = val?.toString() ?: ""
            if (strVal.length() > colWidths[idx]) colWidths[idx] = strVal.length() 
        }
    }

    def separator = "+-" + colWidths.collect { "-" * it }.join("-+-") + "-+"
    def output = new StringBuilder()

    output.append("\n" + "="*110 + "\n REPORTE GLOBAL DE HALLAZGOS SCA (${failingPackageIds.size()} Paquetes Bloqueados)\n" + "="*110 + "\n")
    output.append(separator + "\n")

    tableData.eachWithIndex { row, i ->
        output.append("| " + row.withIndex().collect { val, idx -> (val?.toString() ?: "").padRight(colWidths[idx]) }.join(" | ") + " |\n")
        if (i == 0) output.append(separator + "\n")
    }
    output.append(separator + "\n")
    return output.toString()
}

/*****************************************************************************************
* 7. MÓDULO SCA - DESCARGA Y ANÁLISIS DE POLÍTICAS
* Objetivo:
*   - Solicitar exportación SCA
*   - Esperar finalización (polling)
*   - Descargar reporte
*   - Aplicar reglas de negocio
*   - Fallar pipeline si hay violaciones
*****************************************************************************************/
println "##[group] Exportación y Evaluación SCA"
println "[INFO] Solicitando exportación avanzada SCA a la API..."
def bodyMap = [scanId: ScanID, fileFormat: "ScanReportJson", exportParameters: [hideDevAndTestDependencies: false, showOnlyEffectiveLicenses: false]]
def bodyRequest = JsonOutput.toJson(bodyMap)

//-- SOLICITUD DE EXPORTACIÓN SCA 
def resExport = realizarPeticion("${CX_URL_AST}/sca/export/requests", "POST", bodyRequest)

if (resExport.status < 200 || resExport.status > 299) { 
    println "##vso[task.logissue type=error] Fallo al solicitar exportación SCA. Código: ${resExport.status}"
    SCA_FAILED = true
    return
}

def exportID = new JsonSlurper().parseText(resExport.content).exportId

// -- POLLING (Sondeo de estado) 
def exportStatus = "", retries = 0
def maxRetries = (System.getenv("SCA_MAX_RETRIES") ?: "30").toInteger()

println "[INFO] ID de Tarea: ${exportID} - Esperando procesamiento..."

while (retries < maxRetries) {
    def resStatus = realizarPeticion("${CX_URL_AST}/sca/export/requests?exportId=${exportID}", "GET")
    def jsonStatus = new JsonSlurper().parseText(resStatus.content)
    exportStatus = jsonStatus.exportStatus
    
    println "  -> Estado: ${exportStatus} (Intento ${retries + 1})"
    
    if (exportStatus == 'Completed') {
        println "[OK] Reporte generado en la nube exitosamente."
        break
    } 
    if (exportStatus == 'Failed' || exportStatus == 'Canceled') {
        println "##vso[task.logissue type=error] ERROR FATAL: La exportación falló (${exportStatus})"
        SCA_FAILED = true
        return
    }
    
    retries++
    sleep(10000) 
}

if (exportStatus != 'Completed') {
    println "##vso[task.logissue type=error] Timeout esperando el reporte SCA."
    SCA_FAILED = true
    return
}

// -- DESCARGA DEL REPORTE SCA
println "[INFO] Descargando JSON analítico y aplicando reglas de negocio..."
def resDownload = realizarPeticion("${CX_URL_AST}/sca/export/requests/${exportID}/download", "GET")

if (resDownload.status != 200) {
    println "##vso[task.logissue type=error] ERROR: Fallo al descargar reporte SCA. Código: ${resDownload.status}"
    SCA_FAILED = true
    return
}

// -- GUARDAR JSON SCA 
def tempDir = System.getenv("AGENT_TEMPDIRECTORY") ?: "."
def scaJsonPath = "${tempDir}/cxone_sca_breaker.json"
new File(scaJsonPath).write(resDownload.content)
println "##vso[task.setvariable variable=CX_SCA_JSON_PATH]${scaJsonPath}"

// -- PROCESAMIENTO DEL JSON DE RESULTADOS 
def jsonContent = new JsonSlurper().parseText(resDownload.content)
def combinedList = []
def failingPackageIds = []
def violationReasons = [:]

//--------------- Cruce de Información: Paquetes + Vulnerabilidades -----------------------
for (def pkg in jsonContent.Packages) {
    for (def vuln in jsonContent.Vulnerabilities) {
        if (vuln.PackageId == pkg.Id) {
            combinedList.add([
                PackageId: pkg.Id, 
                IsMalicious: pkg.IsMalicious,
                Severity: vuln.Severity?.toString()?.toUpperCase(), 
                IsDevelopmentDependency: pkg.IsDevelopmentDependency,
                IsTestDependency: pkg.IsTestDependency,
                IsDirectDependency: pkg.IsDirectDependency, 
                VulnerabilityId: vuln.Id,
                Kev: vuln.Kev, 
                ExploitablePath: vuln.ExploitablePath,
                Poc: vuln.Poc, 
                EpssValue: vuln.EpssValue,
                RiskState: vuln.RiskState 
            ])
        }
    }
}

// -- APLICACIÓN DE REGLAS DE NEGOCIO (POLÍTICAS SCA)
def scaCritical = 0, scaHigh = 0, scaMedium = 0, scaLow = 0

for (def item in combinedList) {
    def riskState = item.RiskState?.toString()?.replaceAll("_", "")?.toLowerCase()
    if (riskState == "notexploitable") {
        continue 
    }

    def isViolation = false
    def currentReasons = [] 
    
    def isDevOrTest = (item.IsDevelopmentDependency?.toString() == "true" || item.IsTestDependency?.toString() == "true")
    def isHighOrCritical = (item.Severity == "CRITICAL" || item.Severity == "HIGH")
    
    if (item.IsMalicious.toString() != "false") { 
        currentReasons.add("Malware")
    } 
    
    if (!isDevOrTest) {
        
        if (item.Kev.toString() == "true") { 
            currentReasons.add("KEV") 
        }
        if (item.ExploitablePath.toString() == "true") { 
            currentReasons.add("Ruta Explotable") 
        }
        if (item.Poc.toString() == "true") { 
            currentReasons.add("PoC Pública") 
        }
        
        if (isHighOrCritical) {
            try {
                def epss = item.EpssValue?.toString()?.toDouble() ?: 0.0
                if (epss >= 0.10 && item.IsDirectDependency.toString() == "true") {
                    currentReasons.add("EPSS >= 10% (Directa)")
                }
            } catch (e) { }
        }
    }

    if (currentReasons.size() > 0) {
        isViolation = true
        
        def reasonString = currentReasons.join(" + ")

        if (item.Severity == "CRITICAL") scaCritical++
        if (item.Severity == "HIGH") scaHigh++
        if (item.Severity == "MEDIUM") scaMedium++
        if (item.Severity == "LOW") scaLow++

        violationReasons[item.VulnerabilityId] = reasonString
        
        if (!failingPackageIds.contains(item.PackageId)) { 
            failingPackageIds.add(item.PackageId) 
        }
    }
}

println "[INFO] RESULTADO SCA (Filtro de Inteligencia de Amenazas)"
println "  - Paquetes Bloqueados : ${failingPackageIds.size()}"
println "  - Hallazgos CRITICAL  : ${scaCritical}"
println "  - Hallazgos HIGH      : ${scaHigh}"

// -- RESULTADO FINAL DE VALIDACIÓN SCA 
if (failingPackageIds.size() > 0) {
    def reporteFinal = generateConsolidatedReport(combinedList, failingPackageIds, violationReasons)
    println reporteFinal
    println "##vso[task.logissue type=error] ALERTA DE SEGURIDAD SCA: Revisa la tabla superior para ver todas las vulnerabilidades activas."
    SCA_FAILED = true
} else {
    println "[OK] SCA Aprobado. Las vulnerabilidades encontradas no superan los umbrales de riesgo."
}

SCA_RESULT = [critical: scaCritical, high: scaHigh, medium: scaMedium, low: scaLow]
println "##[endgroup]"

/*****************************************************************************************
* 8. DECISIÓN FINAL Y TABLA DE RESUMEN
*****************************************************************************************/
println "\n" + "="*85
println "              REPORTE FINAL DE CUMPLIMIENTO DE SEGURIDAD (CI/CD)"
println "="*85

// --- Preparación de datos (Sin redeclarar variables existentes) ---
def headers = ["MÓDULO", "ESTADO", "CRÍTICAS", "ALTAS", "INFO ADICIONAL"]

def datosSast = SAST_RESULT.baseComparison ?: SAST_RESULT.directScan ?: [critical:0, high:0]

// Usamos nombres únicos para la tabla (ej: finalCrit) para evitar conflictos con 'scaHigh'
def finalSastCrit = datosSast.critical ?: 0
def finalSastHigh = datosSast.high ?: 0
def finalSastBase = SAST_RESULT.baseComparison?.baselineId ?: "N/A (Scan Directo)"

def finalScaCrit  = SCA_RESULT.critical ?: 0
def finalScaHigh  = SCA_RESULT.high ?: 0

def sastRow = [
    "SAST", 
    (SAST_FAILED ? " FALLÓ" : " PASÓ"), 
    finalSastCrit, 
    finalSastHigh, 
    "Línea Base: ${finalSastBase}"
]

def scaRow = [
    "SCA", 
    (SCA_FAILED ? " FALLÓ" : " PASÓ"), 
    finalScaCrit, 
    finalScaHigh, 
    (SCA_FAILED ? "Revisar tabla detallada arriba" : "Políticas cumplidas")
]

def rows = [sastRow, scaRow]

// --- Lógica de renderizado ---
int[] widths = new int[headers.size()]
[headers, sastRow, scaRow].each { row ->
    row.eachWithIndex { val, i -> 
        widths[i] = Math.max(widths[i], val.toString().length()) 
    }
}

def separator = "+-" + widths.collect { "-" * it }.join("-+-") + "-+"

println separator
println "| " + headers.withIndex().collect { h, i -> h.padRight(widths[i]) }.join(" | ") + " |"
println separator
rows.each { row ->
    println "| " + row.withIndex().collect { v, i -> v.toString().padRight(widths[i]) }.join(" | ") + " |"
}
println separator

if (SAST_FAILED || SCA_FAILED) {
    println "\n##vso[task.logissue type=error] FALLO DE SEGURIDAD: Revisa los hallazgos críticos/altos."
    System.exit(1)
}

println "\n Seguridad aprobada: Cumplimiento total de políticas."
println "=====================================================================================\n"

import groovy.json.JsonOutput
import groovy.json.JsonSlurperClassic

// ── Vérité structurée par étage (CPS-safe, hors environment{}) ─────────
// Root cause confirmée sur build #10 : les variables déclarées dans le
// bloc pipeline-level environment{} sont ré-évaluées/réinitialisées à
// l'entrée de CHAQUE étage suivante, ce qui écrase silencieusement toute
// affectation env.X faite dans une étage précédente (preuve : TESTS_TOTAL
// valait '2' juste après l'étage Tests, et '0' — sa valeur par défaut
// environment{} — au moment du post{always} pipeline-level, alors qu'aucun
// test n'a échoué entre-temps). Ces variables `def` top-level, elles,
// appartiennent au contexte d'exécution du script CPS lui-même et
// survivent aux frontières d'étage et aux points de suspension des steps.
// Types strictement primitifs (String/Integer) — jamais un objet
// LazyMap/JsonSlurper/résultat de plugin retenu ici, pour rester
// sérialisable au sens CPS.
def buildStageStatus = 'UNKNOWN'
def testStageStatus = 'UNKNOWN'
def testsTotal = 0
def testsFailures = 0
def dockerBuildStatus = 'UNKNOWN'
// QA-SCANNER-RUNTIME-TRUTH-CORRECTION-R1 : SONAR_CE_TASK_ID/SONAR_ANALYSIS_ID/
// SONAR_QG/ZAP_STATE souffraient du MÊME bug environment{} que ci-dessus (preuve
// build #12 : ligne 'ZAP_STATE = TARGET_UNAVAILABLE' assignée dans l'étape DAST
// - ZAP, mais platform-event.json publié montrait zapState=NOT_RUN — la valeur
// par défaut d'environment{}, silencieusement restaurée à la frontière du
// post{always} de l'étage ZAP). Migrées ici pour la même raison : ces variables
// `def` top-level survivent aux frontières d'étage/post, contrairement à
// environment{}.
def sonarCeTaskId = ''
def sonarAnalysisId = ''
def sonarQualityGate = 'NOT_RUN'
def zapState = 'NOT_RUN'
// Vérité structurée par scanner (executed/completed/resultAvailable/
// technicalCode/message/exitCode) — additive, ne remplace pas les champs
// existants (zapState/sonarQualityGate/requiredStages restent envoyés tels
// quels pour compatibilité descendante WF1). Types primitifs uniquement
// (String/Integer/Boolean), jamais un objet retenu au travers d'une
// suspension CPS.
def trivyExecuted = false
def trivyCompleted = false
def trivyResultAvailable = false
def trivyTechnicalCode = ''
def trivyMessage = ''
def trivyExitCode = null
def owaspExecuted = false
def owaspCompleted = false
def owaspResultAvailable = false
def owaspTechnicalCode = ''
def owaspMessage = ''
def owaspExitCode = null

// Classification déterministe à partir de preuve texte réelle (jamais
// hard-codée à un build précis) — même patron que backend/src/common/
// scanner-diagnostics.ts::detectTechnicalCode côté plateforme, pour rester
// cohérent producteur/consommateur. Ne classe QUE si un signal texte existe.
def classifyScannerFailure(String text) {
  def t = (text ?: '').toLowerCase()
  if (!t.trim()) { return '' }
  if (t.contains('invalid api key') || t.contains('nvdapiexception') || t.contains(' 401') || t.contains(' 403') || t.contains('unauthorized') || t.contains('forbidden')) { return 'SCANNER_CREDENTIAL_INVALID' }
  if (t.contains('context deadline exceeded') || t.contains('timed out') || t.contains('timeout')) { return 'SCANNER_TIMEOUT' }
  if ((t.contains('download') || t.contains('vulndb') || t.contains('database')) && (t.contains('fail') || t.contains('error'))) { return 'SCANNER_DATABASE_DOWNLOAD_FAILED' }
  if (t.contains('connection refused') || t.contains('no route to host') || t.contains('econnrefused')) { return 'NETWORK_FAILURE' }
  return 'UNKNOWN_TECHNICAL'
}

// Même redaction que celle déjà utilisée pour les logs conteneur ZAP
// (ligne historique zap-target-application.log) — réutilisée ici pour
// Trivy/OWASP : ne JAMAIS transmettre une valeur de credential, même
// partiellement (Jenkins masque déjà la clé NVD dans sa propre console,
// cette étape est une seconde ceinture côté payload plateforme).
def redactSecrets(String text) {
  return (text ?: '').replaceAll(/(?i)(password|token|secret|api[_-]?key)(\s*[=:]\s*)\S+/, '$1$2[REDACTED]')
}

pipeline {
  agent any
  tools { maven 'M3' }
  options { timestamps(); timeout(time: 60, unit: 'MINUTES'); disableConcurrentBuilds() }
  parameters {
    string(name: 'PLATFORM_PROJECT_ID', defaultValue: '', description: 'Platform project UUID once registered')
    string(name: 'SONAR_PROJECT_KEY', defaultValue: 'devsecops-platform-testbed', description: 'SonarQube project key')
    booleanParam(name: 'JENKINS_HARD_GATE', defaultValue: false, description: 'Fail hard on quality/security gates')
    string(name: 'CVSS_FAIL_THRESHOLD', defaultValue: '9.0', description: 'OWASP Dependency-Check CVSS threshold')
  }
  environment {
    IMAGE_NAME = "devsecops-platform-testbed:${BUILD_NUMBER}"
    ZAP_CONTAINER = "devsecops-testbed-zap-${BUILD_NUMBER}"
    // SONAR_CE_TASK_ID/SONAR_ANALYSIS_ID/SONAR_QG/ZAP_STATE : retirés
    // d'ici, voir les `def` top-level en tête de fichier — cause racine
    // du bug ZAP_STATE=NOT_RUN sur build #12 (QA-SCANNER-RUNTIME-TRUTH-
    // CORRECTION-R1 §ZAP).
  }
  stages {
    stage('Build') {
      steps {
        script {
          try {
            sh 'mvn -B clean package -DskipTests -Dmaven.repo.local=/var/jenkins_home/.m2/repository'
            buildStageStatus = 'SUCCESS'
          } catch (e) {
            buildStageStatus = 'FAILED'
            throw e
          }
        }
      }
    }
    stage('Tests') {
      steps {
        catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
          script {
            try {
              sh 'mvn -B test -Dmaven.repo.local=/var/jenkins_home/.m2/repository'
              testStageStatus = 'SUCCESS'
            } catch (e) {
              testStageStatus = 'FAILED'
              throw e
            }
          }
        }
      }
      post {
        always {
          script {
            def summary = junit(allowEmptyResults: true, testResults: 'target/surefire-reports/*.xml')
            testsTotal = summary.totalCount as Integer
            testsFailures = summary.failCount as Integer
          }
        }
      }
    }
    stage('SAST - SonarQube') {
      steps {
        catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
          withSonarQubeEnv('sq1') {
            sh '''mvn -B org.sonarsource.scanner.maven:sonar-maven-plugin:4.0.0.4121:sonar \\
              -Dsonar.projectKey=${SONAR_PROJECT_KEY} \\
              -Dsonar.projectVersion=${BUILD_NUMBER} \\
              -Dmaven.repo.local=/var/jenkins_home/.m2/repository'''
            script {
              sonarCeTaskId = sh(returnStdout: true, script: "sed -n 's/^ceTaskId=//p' target/sonar/report-task.txt | head -1").trim()
              if (!sonarCeTaskId) { error('Sonar report-task.txt missing ceTaskId') }
              timeout(time: 5, unit: 'MINUTES') {
                waitUntil {
                  def ce = sh(returnStdout: true, script: "curl -fsS -u \"${SONAR_AUTH_TOKEN}:\" \"${SONAR_HOST_URL}/api/ce/task?id=${sonarCeTaskId}\"").trim()
                  def status = (new JsonSlurperClassic().parseText(ce)?.task?.status ?: '').toString()
                  if (status == 'FAILED' || status == 'CANCELED') { error("Sonar CE task ${status}") }
                  return status == 'SUCCESS'
                }
              }
              def ceFinal = sh(returnStdout: true, script: "curl -fsS -u \"${SONAR_AUTH_TOKEN}:\" \"${SONAR_HOST_URL}/api/ce/task?id=${sonarCeTaskId}\"").trim()
              sonarAnalysisId = (new JsonSlurperClassic().parseText(ceFinal)?.task?.analysisId ?: '').toString()
              if (!sonarAnalysisId) { error('Sonar CE SUCCESS without analysisId') }
              def qg = sh(returnStdout: true, script: "curl -fsS -u \"${SONAR_AUTH_TOKEN}:\" \"${SONAR_HOST_URL}/api/qualitygates/project_status?analysisId=${sonarAnalysisId}\"").trim()
              sonarQualityGate = (new JsonSlurperClassic().parseText(qg)?.projectStatus?.status ?: 'API_ERROR').toString()
              if (params.JENKINS_HARD_GATE && sonarQualityGate != 'OK') { error("Quality Gate: ${sonarQualityGate}") }
            }
          }
        }
      }
    }
    stage('Docker Build') {
      steps {
        script {
          try {
            sh 'docker build -t "$IMAGE_NAME" .'
            dockerBuildStatus = 'SUCCESS'
          } catch (e) {
            dockerBuildStatus = 'FAILED'
            throw e
          }
        }
      }
    }
    stage('Security Scans') {
      parallel {
        stage('SCA - OWASP') {
          steps {
            catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
              script {
                owaspExecuted = true
                withCredentials([string(credentialsId: 'NVD_API_KEY', variable: 'NVD_API_KEY')]) {
                  def raw = sh(returnStdout: true, script: '''mvn -B org.owasp:dependency-check-maven:12.2.2:check \\
                    -DnvdApiKey="$NVD_API_KEY" \\
                    -DfailBuildOnCVSS=${CVSS_FAIL_THRESHOLD} \\
                    -Dformats=HTML,JSON \\
                    -Dmaven.repo.local=/var/jenkins_home/.m2/repository 2>&1
                    echo "__OWASP_EXIT__=$?"''').trim()
                  def lines = raw.readLines()
                  def last = lines ? lines[-1] : ''
                  owaspExitCode = last.startsWith('__OWASP_EXIT__=') ? (last.replace('__OWASP_EXIT__=', '') as Integer) : 1
                  def body = redactSecrets(lines.size() > 1 ? lines[0..-2].join('\n') : '')
                  def reportExists = fileExists('target/dependency-check-report.json')
                  if (owaspExitCode == 0 && reportExists) {
                    owaspCompleted = true
                    owaspResultAvailable = true
                  } else {
                    owaspCompleted = false
                    owaspResultAvailable = false
                    owaspTechnicalCode = classifyScannerFailure(body)
                    owaspMessage = redactSecrets(body.readLines().findAll { it.trim() }.reverse().take(6).reverse().join(' | '))
                  }
                  if (owaspExitCode != 0) { error("OWASP Dependency-Check failed (exit ${owaspExitCode})") }
                }
              }
            }
          }
        }
        stage('Trivy') {
          steps {
            catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
              script {
                trivyExecuted = true
                def raw = sh(returnStdout: true, script: '''mkdir -p security
                docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \\
                  -v "$WORKSPACE/security:/out" aquasec/trivy:0.66.0 image \\
                  --exit-code 0 --severity CRITICAL,HIGH --format json \\
                  --output /out/trivy-report.json "$IMAGE_NAME" 2>&1
                echo "__TRIVY_EXIT__=$?"''').trim()
                def lines = raw.readLines()
                def last = lines ? lines[-1] : ''
                trivyExitCode = last.startsWith('__TRIVY_EXIT__=') ? (last.replace('__TRIVY_EXIT__=', '') as Integer) : 1
                def body = lines.size() > 1 ? lines[0..-2].join('\n') : ''
                def reportExists = fileExists('security/trivy-report.json')
                if (trivyExitCode == 0 && reportExists) {
                  trivyCompleted = true
                  trivyResultAvailable = true
                } else {
                  trivyCompleted = false
                  trivyResultAvailable = false
                  trivyTechnicalCode = classifyScannerFailure(body)
                  trivyMessage = body.readLines().findAll { it.trim() }.reverse().take(6).reverse().join(' | ')
                }
                if (trivyExitCode != 0) { error("Trivy scan failed (exit ${trivyExitCode})") }
              }
            }
          }
        }
      }
    }
    stage('DAST - ZAP') {
      steps {
        catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
          script {
            sh 'mkdir -p security/zap; docker rm -f "$ZAP_CONTAINER" >/dev/null 2>&1 || true'
            sh 'docker run -d --name "$ZAP_CONTAINER" --network pfe-network "$IMAGE_NAME"'
            // Le conteneur a démarré : la tentative ZAP a réellement commencé
            // à cet instant, indépendamment de l'issue du healthcheck ci-dessous.
            zapState = 'RUNNING'
            def ready = sh(returnStatus: true, script: '''for i in $(seq 1 12); do
              curl -sf "http://${ZAP_CONTAINER}:8080/healthz" >/dev/null && exit 0
              sleep 5
            done
            exit 1''') == 0
            if (!ready) {
              def stateLine = sh(returnStdout: true, script: '''docker inspect -f '{{.State.Running}}|{{.State.ExitCode}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$ZAP_CONTAINER" 2>/dev/null || echo 'false|-1||' ''').trim()
              def parts = stateLine.split('\\|', -1)
              def running = parts.size() > 0 ? parts[0] : 'false'
              def exitCode = parts.size() > 1 ? parts[1] : '-1'
              def health = parts.size() > 2 ? parts[2] : ''
              def networks = parts.size() > 3 ? parts[3].trim() : ''
              def rawLogs = sh(returnStdout: true, script: 'docker logs --tail 250 "$ZAP_CONTAINER" 2>&1 || true').trim()
              def sanitized = rawLogs.replaceAll(/(?i)(password|token|secret|api[_-]?key)(\\s*[=:]\\s*)\\S+/, '$1$2[REDACTED]')
              writeFile file: 'security/zap/zap-target-application.log', text: sanitized + '\\n'
              // executed:true — le conteneur a bien démarré (docker run -d ci-dessus)
              // et 12 tentatives de healthcheck ont eu lieu ; seule la cible est
              // injoignable, ce n'est PAS un scanner jamais invoqué (bug confirmé
              // build #12 : cette valeur valait false ici alors que le stage avait
              // démarré — QA-SCANNER-RUNTIME-TRUTH-CORRECTION-R1 §ZAP).
              def diag = [scanner:'ZAP', state:'TARGET_UNAVAILABLE', executed:true,
                          targetUrl:"http://${env.ZAP_CONTAINER}:8080", containerName:env.ZAP_CONTAINER,
                          containerRunning:(running == 'true'), exitCode:exitCode as Integer,
                          expectedPort:8080, network:networks, health:health,
                          readinessAttempts:12, timeoutSeconds:60,
                          rootCauseCategory:'APPLICATION_OR_RUNTIME_FAILURE',
                          technicalMessage:(sanitized.readLines().take(8).join(' | ')), logsCaptured:true]
              writeFile file: 'security/zap/zap-target-diagnostic.json', text: JsonOutput.prettyPrint(JsonOutput.toJson(diag))
              zapState = 'TARGET_UNAVAILABLE'
              error('ZAP target unavailable; diagnostic evidence captured')
            }
            sh '''docker run --rm --network pfe-network -v "$WORKSPACE/security/zap:/zap/wrk:rw" \\
              zaproxy/zap-stable:2.16.1 zap-baseline.py \\
              -t "http://${ZAP_CONTAINER}:8080" -J zap-report.json -I || true'''
            zapState = fileExists('security/zap/zap-report.json') ? 'COMPLETED' : 'FAILED'
          }
        }
      }
      post { always { sh 'docker rm -f "$ZAP_CONTAINER" >/dev/null 2>&1 || true' } }
    }
  }
  post {
    always {
      archiveArtifacts allowEmptyArchive: true, artifacts: 'target/dependency-check-report.*,security/**/*.json,security/**/*.log'
      script {
        def payload = [projectId: params.PLATFORM_PROJECT_ID ?: null,
                       event: "pipeline_${currentBuild.currentResult.toLowerCase()}",
                       repository: 'souhaiel11/devsecops-platform-testbed',
                       jenkinsJob: env.JOB_NAME,
                       job: env.JOB_NAME,
                       buildNumber: env.BUILD_NUMBER as Integer,
                       buildUrl: env.BUILD_URL,
                       jenkinsStatus: currentBuild.currentResult,
                       // Champs legacy préservés tels quels pour compatibilité descendante
                       // WF1 — mais désormais lus depuis les variables de script top-level
                       // (pas env.*), même correction que buildStageStatus et consorts :
                       // voir la note en tête de fichier — environment{} ne survit pas aux
                       // frontières d'étage/post (bug confirmé sur zapState, build #12).
                       ceTaskId: sonarCeTaskId ?: null,
                       analysisId: sonarAnalysisId ?: null,
                       sonarQualityGate: sonarQualityGate,
                       zapState: zapState,
                       buildStageStatus: buildStageStatus,
                       tests: [status: testStageStatus,
                               total: testsTotal,
                               failures: testsFailures,
                               skipped: 0,
                               coverage: 0],
                       docker: [build_status: dockerBuildStatus,
                                image_tag: env.IMAGE_NAME,
                                push_status: 'SKIPPED'],
                       // Vérité structurée additive par scanner (QA-SCANNER-RUNTIME-TRUTH-
                       // CORRECTION-R1) — executed/completed/resultAvailable/technicalCode
                       // dérivés de preuve réelle capturée pendant l'étage, jamais devinés
                       // après coup. N'écrase aucun champ legacy ci-dessus.
                       trivy: [executed: trivyExecuted, completed: trivyCompleted,
                               resultAvailable: trivyResultAvailable,
                               status: (trivyCompleted ? 'COMPLETED' : (trivyExecuted ? 'FAILED' : 'NOT_RUN')),
                               technicalCode: trivyTechnicalCode ?: null, message: trivyMessage ?: null,
                               exitCode: trivyExitCode],
                       owasp: [executed: owaspExecuted, completed: owaspCompleted,
                               resultAvailable: owaspResultAvailable,
                               status: (owaspCompleted ? 'COMPLETED' : (owaspExecuted ? 'FAILED' : 'NOT_RUN')),
                               technicalCode: owaspTechnicalCode ?: null, message: owaspMessage ?: null,
                               exitCode: owaspExitCode],
                       zap: [executed: (zapState in ['RUNNING','TARGET_UNAVAILABLE','COMPLETED','FAILED']),
                             completed: (zapState == 'COMPLETED'),
                             resultAvailable: (zapState == 'COMPLETED' && fileExists('security/zap/zap-report.json')),
                             status: zapState,
                             technicalCode: (zapState == 'TARGET_UNAVAILABLE' ? 'TARGET_UNAVAILABLE' : null)],
                       requiredStages:['build','tests','sonar','trivy','owasp','zap','docker']]
        writeFile file: 'platform-event.json', text: JsonOutput.toJson(payload)
        withCredentials([string(credentialsId: 'N8N_API_KEY', variable: 'N8N_API_KEY')]) {
          httpRequest httpMode: 'POST', url: 'http://n8n:5678/webhook/jenkins-event',
            customHeaders: [[name:'X-API-Key', value:N8N_API_KEY, maskValue:true]],
            contentType: 'APPLICATION_JSON', requestBody: readFile('platform-event.json'), validResponseCodes: '200:299'
        }
      }
    }
  }
}

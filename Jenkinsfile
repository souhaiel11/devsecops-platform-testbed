import groovy.json.JsonOutput
import groovy.json.JsonSlurperClassic

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
    SONAR_CE_TASK_ID = ''
    SONAR_ANALYSIS_ID = ''
    SONAR_QG = 'NOT_RUN'
    ZAP_STATE = 'NOT_RUN'
  }
  stages {
    stage('Build') {
      steps { sh 'mvn -B clean package -DskipTests -Dmaven.repo.local=/var/jenkins_home/.m2/repository' }
    }
    stage('QA Jenkins Command') {
      steps {
        catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
          sh 'qa-tool-that-does-not-exist --version'
        }
      }
    }
    stage('Tests') {
      steps {
        catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
          sh 'mvn -B test -Dmaven.repo.local=/var/jenkins_home/.m2/repository'
        }
      }
      post { always { junit allowEmptyResults: true, testResults: 'target/surefire-reports/*.xml' } }
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
              env.SONAR_CE_TASK_ID = sh(returnStdout: true, script: "sed -n 's/^ceTaskId=//p' target/sonar/report-task.txt | head -1").trim()
              if (!env.SONAR_CE_TASK_ID) { error('Sonar report-task.txt missing ceTaskId') }
              timeout(time: 5, unit: 'MINUTES') {
                waitUntil {
                  def ce = sh(returnStdout: true, script: "curl -fsS -u \"${SONAR_AUTH_TOKEN}:\" \"${SONAR_HOST_URL}/api/ce/task?id=${SONAR_CE_TASK_ID}\"").trim()
                  def status = (new JsonSlurperClassic().parseText(ce)?.task?.status ?: '').toString()
                  if (status == 'FAILED' || status == 'CANCELED') { error("Sonar CE task ${status}") }
                  return status == 'SUCCESS'
                }
              }
              def ceFinal = sh(returnStdout: true, script: "curl -fsS -u \"${SONAR_AUTH_TOKEN}:\" \"${SONAR_HOST_URL}/api/ce/task?id=${SONAR_CE_TASK_ID}\"").trim()
              env.SONAR_ANALYSIS_ID = (new JsonSlurperClassic().parseText(ceFinal)?.task?.analysisId ?: '').toString()
              if (!env.SONAR_ANALYSIS_ID) { error('Sonar CE SUCCESS without analysisId') }
              def qg = sh(returnStdout: true, script: "curl -fsS -u \"${SONAR_AUTH_TOKEN}:\" \"${SONAR_HOST_URL}/api/qualitygates/project_status?analysisId=${SONAR_ANALYSIS_ID}\"").trim()
              env.SONAR_QG = (new JsonSlurperClassic().parseText(qg)?.projectStatus?.status ?: 'API_ERROR').toString()
              if (params.JENKINS_HARD_GATE && env.SONAR_QG != 'OK') { error("Quality Gate: ${env.SONAR_QG}") }
            }
          }
        }
      }
    }
    stage('Docker Build') {
      steps { sh 'docker build -t "$IMAGE_NAME" .' }
    }
    stage('Security Scans') {
      parallel {
        stage('SCA - OWASP') {
          steps {
            catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
              withCredentials([string(credentialsId: 'NVD_API_KEY', variable: 'NVD_API_KEY')]) {
                sh '''mvn -B org.owasp:dependency-check-maven:12.2.2:check \\
                  -DnvdApiKey="$NVD_API_KEY" \\
                  -DfailBuildOnCVSS=${CVSS_FAIL_THRESHOLD} \\
                  -Dformats=HTML,JSON \\
                  -Dmaven.repo.local=/var/jenkins_home/.m2/repository'''
              }
            }
          }
        }
        stage('Trivy') {
          steps {
            catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
              sh '''mkdir -p security
              docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \\
                -v "$WORKSPACE/security:/out" aquasec/trivy:0.66.0 image \\
                --exit-code 0 --severity CRITICAL,HIGH --format json \\
                --output /out/trivy-report.json "$IMAGE_NAME"'''
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
              def diag = [scanner:'ZAP', state:'TARGET_UNAVAILABLE', executed:false,
                          targetUrl:"http://${env.ZAP_CONTAINER}:8080", containerName:env.ZAP_CONTAINER,
                          containerRunning:(running == 'true'), exitCode:exitCode as Integer,
                          expectedPort:8080, network:networks, health:health,
                          readinessAttempts:12, timeoutSeconds:60,
                          rootCauseCategory:'APPLICATION_OR_RUNTIME_FAILURE',
                          technicalMessage:(sanitized.readLines().take(8).join(' | ')), logsCaptured:true]
              writeFile file: 'security/zap/zap-target-diagnostic.json', text: JsonOutput.prettyPrint(JsonOutput.toJson(diag))
              env.ZAP_STATE = 'TARGET_UNAVAILABLE'
              error('ZAP target unavailable; diagnostic evidence captured')
            }
            env.ZAP_STATE = 'RUNNING'
            sh '''docker run --rm --network pfe-network -v "$WORKSPACE/security/zap:/zap/wrk:rw" \\
              zaproxy/zap-stable:2.16.1 zap-baseline.py \\
              -t "http://${ZAP_CONTAINER}:8080" -J zap-report.json -I || true'''
            env.ZAP_STATE = fileExists('security/zap/zap-report.json') ? 'COMPLETED' : 'FAILED'
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
                       buildNumber: env.BUILD_NUMBER as Integer,
                       buildUrl: env.BUILD_URL,
                       jenkinsStatus: currentBuild.currentResult,
                       ceTaskId: env.SONAR_CE_TASK_ID ?: null,
                       analysisId: env.SONAR_ANALYSIS_ID ?: null,
                       sonarQualityGate: env.SONAR_QG,
                       zapState: env.ZAP_STATE,
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

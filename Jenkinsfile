pipeline {
  agent any

  tools {
    jdk   'jdk17'       // configure under Manage Jenkins > Tools
    maven 'maven3'
  }

  parameters {
    string(name: 'CATEGORIES', defaultValue: 'SAST,SCA,SECRETS,CLOUD', description: 'Scanner categories to run')
    string(name: 'TARGET_URL', defaultValue: '', description: 'Staging URL for DAST/API (must be in scan.allowed.hosts)')
    booleanParam(name: 'ENFORCE_GATE', defaultValue: true, description: 'Fail the build when the quality gate fails')
  }

  triggers { cron('H 2 * * *') }

  options {
    timestamps()
    timeout(time: 90, unit: 'MINUTES')
    buildDiscarder(logRotator(numToKeepStr: '30'))
  }

  environment {
    SONAR_TOKEN       = credentials('sonar-token')
    SNYK_TOKEN        = credentials('snyk-token')
    SLACK_WEBHOOK_URL = credentials('slack-webhook')
    BUILD_URL_LINK    = "${env.BUILD_URL}"
  }

  stages {
    stage('Build & Unit Test') {
      steps { sh 'mvn -B -ntp clean verify' }
      post { always { junit 'target/surefire-reports/*.xml' } }
    }

    stage('Static Security Scans') {
      steps {
        sh """
          java -jar target/security-framework.jar \
            --categories=${params.CATEGORIES} \
            --name=${env.JOB_BASE_NAME} \
            --source=. \
            --out=target/security-reports \
            ${params.ENFORCE_GATE ? '' : '--no-gate'}
        """
      }
    }

    stage('Dynamic Security Scans') {
      when { expression { params.TARGET_URL?.trim() } }
      steps {
        sh """
          java -jar target/security-framework.jar \
            --scanners=zap,nuclei,owasp-api-top10 \
            --url=${params.TARGET_URL} \
            --name=${env.JOB_BASE_NAME}-dast \
            --out=target/security-reports-dast \
            ${params.ENFORCE_GATE ? '' : '--no-gate'}
        """
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'target/security-reports*/**', allowEmptyArchive: true
      publishHTML(target: [reportDir: 'target/security-reports', reportFiles: 'security-report.html',
                           reportName: 'Security Report', keepAll: true, allowMissing: true, alwaysLinkToLastBuild: true])
    }
  }
}

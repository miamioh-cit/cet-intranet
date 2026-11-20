pipeline {
    agent any
    options {
        skipDefaultCheckout(true)
        disableConcurrentBuilds()
    }
    environment {
        DOCKER_CREDENTIALS_ID = 'roseaw-dockerhub'  
        DOCKER_IMAGE = 'cithit/cit-intranet'                       
        IMAGE_TAG = "intranet-new-${BUILD_NUMBER}"
        KUBECONFIG = credentials('cet-intranet1')
        KUBE_NAMESPACE = 'cet-intranet'                           
    }
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        stage('Build Docker Image') {
            steps {
                script {
                    docker.build("${DOCKER_IMAGE}:${IMAGE_TAG}")
                }
            }
        }
        stage('Push Docker Image') {
            steps {
                script {
                    docker.withRegistry('https://index.docker.io/v1/', "${DOCKER_CREDENTIALS_ID}") {
                        docker.image("${DOCKER_IMAGE}:${IMAGE_TAG}").push()
                    }
                }
            }
        }
        stage('Deploy to Prod Environment') {
            steps {
                script {
                    // Update both Nginx and staff-auth to the image built by this job.
                    sh "sed -i 's|${DOCKER_IMAGE}:latest|${DOCKER_IMAGE}:${IMAGE_TAG}|g' deployment-prod.yaml"
                    sh '''
                        set -eu
                        kubectl -n "$KUBE_NAMESPACE" get deployments >/dev/null
                        kubectl -n "$KUBE_NAMESPACE" get secret intranet-admin-auth >/dev/null
                        kubectl apply --dry-run=server -n "$KUBE_NAMESPACE" -f deployment-prod.yaml
                        kubectl apply -n "$KUBE_NAMESPACE" -f deployment-prod.yaml
                        kubectl -n "$KUBE_NAMESPACE" rollout status deployment/prod-deployment --timeout=300s
                    '''
                }
            }
        }
        stage('Check Kubernetes Cluster') {
            steps {
                sh 'kubectl -n "$KUBE_NAMESPACE" get pods,services,deployments'
            }
        }
    }
    post {
        success {
            slackSend color: "good", message: "Build Completed: ${env.JOB_NAME} ${env.BUILD_NUMBER}"
        }
            
        unstable {
            slackSend color: "warning", message: "Build Completed: ${env.JOB_NAME} ${env.BUILD_NUMBER}"
        }
            
        failure {
            slackSend color: "danger", message: "Build Completed: ${env.JOB_NAME} ${env.BUILD_NUMBER}"
        }
    }
}

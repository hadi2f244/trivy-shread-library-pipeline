
def loadProperties(path) {
    properties = new Properties()
    File propertiesFile = new File(path)
    properties.load(propertiesFile.newDataInputStream())
    Set<Object> keys = properties.keySet();
    for(Object k:keys){
    String key = (String)k;
    String value =(String) properties.getProperty(key)
    env."${key}" = "${value}"
    }
}
def getCurrentBranch () {
    return sh (
        script: 'git rev-parse --abbrev-ref HEAD',
        returnStdout: true
    ).trim()
}
def getLatestCommit () {
   return sh (
        script: 'git rev-parse --short HEAD',
        returnStdout: true
    ).trim()
}

def call(body){

	// evaluate the body block, and collect configuration into the object
	def pipelineParams= [:]
	body.resolveStrategy = Closure.DELEGATE_FIRST
	body.delegate = pipelineParams
	body()


	pipeline {
	    agent any
	    environment {
			def APP_NAME = "test"
			def BRANCH_NAME = "main"
			def SHORT_COMMIT = "1234"
	    }
	    stages {
			stage('Load code') {
				steps {
					script {
						checkout([$class: 'GitSCM', branches: [[name: '*/main']], doGenerateSubmoduleConfigurations: false, extensions: [[$class: 'RelativeTargetDirectory', relativeTargetDir: '.']], extensions: [[$class: 'LocalBranch', localBranch: "**"]], submoduleCfg: [], userRemoteConfigs: [[url: 'https://github.com/hadi2f244/trivy-shread-library-pipeline-withoutjenkinsfile']]])
					}
				}
        	}
			stage('Print Variables') {
				steps{
					// Passed vars
					echo "${pipelineParams}"
					// Global vars
					echo "${BRANCH_NAME}"
				}
			}
	        stage('Build Image') {
	            steps {
	                script {
	                    dockerImage = docker.build("${APP_NAME}:${BRANCH_NAME}-${SHORT_COMMIT}", "--pull --build-arg BRANCH=${BRANCH_NAME} --build-arg COMMIT=${SHORT_COMMIT} .")
	                }
	            }
	        }
	        stage('Load Environment Variables') {
	            steps {
	                script {
						sh "cat ${workspace}/jenkins/env.groovy"
	                	//load "${workspace}/jenkins/env.groovy"
						loadProperties("${workspace}/jenkins/env.groovy")
						sh 'printenv'
	                }
	            }
	        }
			stage("Test Credentials"){
				steps {
					script {
						withCredentials([string(credentialsId: 'GITHUB_TOKEN', variable: 'GITHUB_TOKEN')]) {
							sh "echo ${env.GITHUB_TOKEN}"
						}
					}
				}
			}
	        stage("Security Scan") {
	            when {
					allOf {
						expression { env.SECURITY_SCAN != null }
		                expression { SECURITY_SCAN == "true" }
					}
	            }
	            environment {
	                VUL_TYPE ="library" // "os,library"
	            }
	            steps {
	                script {
	                    // Create trivy ignore policy
	                    def ignore_policy_rego_file = ""
	                    if (env.IGNORE_PKGS != null && IGNORE_PKGS?.trim()){
	                        ignore_policy_rego_file = sh(returnStdout: true, script: 'mktemp --suffix=.rego').trim()
	                        sh """
	                        cat > ${ignore_policy_rego_file} <<EOF
	                        package trivy
	                        import data.lib.trivy
	                        default ignore = false
	                        ignore_pkgs := ${IGNORE_PKGS}
	                        ignore {
	                            input.PkgName == ignore_pkgs[_]
	                        }
	                        """
	                    }

	                    // Trivy Security Check
	                    // HTTP Proxy
	                    def proxy_set_var = ""
	                    if (env.HTTP_PROXY?.trim()){
	                        proxy_set_var = " --env HTTP_PROXY=\"${pipelineParams.HTTP_PROXY}\" --env HTTPS_PROXY=\"${pipelineParams.HTTP_PROXY}\""
	                    }

	                    // Ignore Policy
	                    def ignore_policy_volume = ""
	                    def ignore_policy_option = ""
	                    if (ignore_policy_rego_file?.trim()){
	                        ignore_policy_volume = "-v ${ignore_policy_rego_file}:${ignore_policy_rego_file}"
	                        ignore_policy_option = "--ignore-policy ${ignore_policy_rego_file}"
	                    }

	                    // Try to check GITHUB_TOKEN existance
	                    try {
	                        sh """
	                            docker run --rm \
	                                -v /var/run/docker.sock:/var/run/docker.sock -v /tmp/trivy:/tmp/trivy \
	                                ${ignore_policy_volume} \
	                                ${proxy_set_var} \
	                                aquasec/trivy:latest --cache-dir /tmp/trivy/ image \
	                                --ignore-unfixed --exit-code 1 --scanners vuln \
	                                --vuln-type ${VUL_TYPE} \
	                                ${ignore_policy_option} \
	                                --severity HIGH,CRITICAL lvthillo/python-flask-docker
	                        """
	                    } catch (Exception e) {
	                        // Throw error to fail pipeline
	                        throw e
	                    } finally {
	                        // Rescure steps:
	                        // Remove ignore_policy_rego_file
	                        if (ignore_policy_rego_file?.trim()){
	                            sh "rm ${ignore_policy_rego_file}"
	                        }

	                    }
	                }
	            }
	        }
	    }
	}
}


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

def call(body){

	// evaluate the body block, and collect configuration into the object
	def pipelineParams= [:]
	body.resolveStrategy = Closure.DELEGATE_FIRST
	body.delegate = pipelineParams
	body()
	
	
	pipeline {
	    agent any
	    environment {
	        APP_NAME = "${pipelineParams.APP_NAME}"
	        SHORT_COMMIT = GIT_COMMIT.take(7)
	        HTTP_PROXY = "${pipelineParams.HTTP_PROXY}"
	    }
	    stages {
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
	                    dockerImage = docker.build("${APP_NAME}:${BRANCH_NAME}-${SHORT_COMMIT}", "--pull --build-arg BRANCH=${BRANCH_NAME} --build-arg COMMIT=${GIT_COMMIT} .")
	                }
	            }
	        }
	        stage('Load Environment Variables') {
	            steps {
	                script {
						sh "cat ${workspace}/jenkins/env.groovy"
	                    load "${workspace}/jenkins/env.groovy"
						sh "echo ${env.SECURITY_SCAN}"
						//loadProperties("${workspace}/jenkins/env.groovy")
						sh 'printenv'
	                }
	            }
	        }
	        stage("Security Scan") {
	            when {
	                expression { env.SECURITY_SCAN == "true" }
	            }
	            environment {
	                VUL_TYPE ="library" // "os,library"
	            }
	            steps {
	                script {
	                    // Create trivy ignore policy
	                    def ignore_policy_rego_file = ""
	                    if (env.IGNORE_PKGS?.trim()){
	                        ignore_policy_rego_file = sh(returnStdout: true, script: 'mktemp --suffix=.rego').trim()
	                        sh """
	                        cat > ${ignore_policy_rego_file} <<EOF
	                        package trivy
	                        import data.lib.trivy
	                        default ignore = false
	                        ignore_pkgs := ${env.IGNORE_PKGS}
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
	                                --severity HIGH,CRITICAL ${APP_NAME}:${BRANCH_NAME}-${SHORT_COMMIT}
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

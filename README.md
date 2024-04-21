# IAM-Verifier
Code validating IAM policy JSON input

**Tech Stack: 
- Java 21
- Junit 4.13.2 framework
-  Package *org.json*, source -> [GithubRepo](https://github.com/stleary/JSON-java?tab=readme-ov-file)

#### **Project Structure:**
-  Source codes for the verifier method and test are inside ***src*** **directory**  ***==main/java/verifier==*** and **==test/java/verifier==** accordingly
- Libraries used in the program are inside ***lib folder*** as jar files
-  Resources as JSON input files are located inside ***JSON_files folder***
- Class path file defining directories of source codes and libraries is located in project's root directory under the name ==**.classpath.xml**== 

#### **Running the program:**
1. After downloading the Task folder navigate in terminal to the folders described above
2.  If you want to just run a singular test file from the provided cases you need to open ==**IAMRolePolicyVerifier.java**== file and define ***jsonFilePath*** variable(after "/") in main method to the naming convention like here:

    -  **For policies returning true**: ==true_policy.json== with addition of number at the beginning in range 2-10

    - **For policies returning false**: ==false_policy.json== with addition of number at the beginning in range 2-5
4. After defining a file you need to run following commands in terminal:

   - **In Windows:**
			`javac -cp ".;.\lib\json-java.jar" .\src\main\java\verifier\IAMRolePolicyVerifier.java`
			`java -cp ".;.\lib\json-java.jar; .\src\main\java" verifier.IAMRolePolicyVerifier`

   -  **In Unix based system**: change "*;" to ":*"

#### **Running tests:**
1. Navigate to project's root directory
2. Run following commands:

   -  **In Windows:**
			`javac -cp ".;.\lib\junit-4.13.2.jar;.\lib\hamcrest-core-1.3.jar;.\lib\json-java.jar" .\src\main\java\verifier\IAMRolePolicyVerifier.java .\src\test\java\verifier\PolicyTests.java`
			`java -cp ".;.\lib\junit-4.13.2.jar;.\lib\hamcrest-core-1.3.jar;.\lib\json-java.jar;.\src\main\java;.\src\test\java" org.junit.runner.JUnitCore verifier.PolicyTests`

   - **In Unix based system:** change "*;" to ":*"


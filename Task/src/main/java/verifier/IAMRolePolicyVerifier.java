package verifier;

import org.json.JSONObject;
import org.json.JSONException;
import org.json.JSONArray;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.IOException;

public class IAMRolePolicyVerifier {

    public static boolean verifyIAMRolePolicy(String jsonFilePath) throws InvalidPolicyConstruct {
        try (BufferedReader reader = new BufferedReader(new FileReader(jsonFilePath))) {
            StringBuilder jsonString = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                jsonString.append(line);
            }

            JSONObject data = new JSONObject(jsonString.toString());
            JSONArray statements;

            // Check for the presence of "Version" field directly under the root object
            if (!data.has("Version") && !data.has("PolicyDocument")) {
                throw new InvalidPolicyConstruct(
                        "Given input does not implement AWS IAM policy correctly: 'Version' field missing");
            }

            // Check if "PolicyDocument" exists and extract "Statement" from it
            if (data.has("PolicyDocument")) {
                JSONObject policyDocument = data.getJSONObject("PolicyDocument");
                if (!policyDocument.has("Version")) {
                    throw new InvalidPolicyConstruct(
                            "Given input does not implement AWS IAM policy correctly: 'Version' field missing");
                }
                if (!policyDocument.has("Statement")) {
                    throw new InvalidPolicyConstruct(
                            "Given input does not implement AWS IAM policy correctly: 'Statement' field missing");
                }
                Object statementField = policyDocument.get("Statement");
                if (statementField instanceof JSONObject) {
                    statements = new JSONArray().put((JSONObject) statementField);
                } else {
                    statements = (JSONArray) statementField;
                }
            } else if (data.has("Statement")) {
                // "Statement" is directly under the root object
                Object statementField = data.get("Statement");
                if (statementField instanceof JSONObject) {
                    statements = new JSONArray().put((JSONObject) statementField);
                } else {
                    statements = (JSONArray) statementField;
                }
            } else {
                throw new InvalidPolicyConstruct(
                        "Given input does not implement AWS IAM policy correctly: 'Statement' field missing");
            }

            boolean hasDesiredResoure = false;
            // Check each statement for required fields
            for (int i = 0; i < statements.length(); i++) {
                JSONObject statement = statements.getJSONObject(i);

                // Check if the statement has the "Effect", "Action", and "Resource" fields
                if (!statement.has("Effect") || !statement.has("Action") || !statement.has("Resource")) {
                    throw new InvalidPolicyConstruct(
                            "Given input does not implement AWS IAM policy correctly: 'Effect', 'Action', or 'Resource' field missing in a statement");
                }

                // Check if the "Action" field is a string or an array
                Object actionField = statement.get("Action");
                if (!(actionField instanceof String || actionField instanceof JSONArray)) {
                    throw new InvalidPolicyConstruct(
                            "Given input does not implement AWS IAM policy correctly: 'Action' field is invalid in a statement");
                }

                // Checking instance of the 'Resource' field
                if (statement.get("Resource") instanceof JSONArray) {

                    for (int j = 0; j < statement.length(); j++) {
                        String resource = statement.toString(j);
                        if ("*".equals(resource.trim()) && resource.length() == 1) {
                            hasDesiredResoure = true;
                        }
                    }
                } else {
                    String resource = statement.getString("Resource");
                    if ("*".equals(resource.trim()) && resource.length() == 1) {
                        hasDesiredResoure = true;
                    }
                }
            }
            if (hasDesiredResoure) {
                return false;
            }
            return true; // No Resource with * found
        } catch (IOException e) {

            System.err.println("Error reading file: " + e.getMessage());
            return true; // File reading error
        } catch (JSONException e) {

            System.err.println("Error parsing JSON: " + e.getMessage());
            return true; // JSON parsing error
        } catch (InvalidPolicyConstruct e) {

            System.err.println("Structure error: " + e.getMessage());
            return true; // Invalid policy structure
        }
    }

    public static class InvalidPolicyConstruct extends Exception {

        public InvalidPolicyConstruct(String message) {
            super(message);
        }
    }

    public static void main(String[] args) throws InvalidPolicyConstruct {
        String jsonFilePath = "JSON_files/5false_policy.json";
        boolean result = verifyIAMRolePolicy(jsonFilePath);
        System.out.println("Verification Result: " + result);
    }
    // Compile: javac -cp ".;.\lib\json-java.jar"
    // .\src\main\java\verifier\IAMRolePolicyVerifier.java
    // Run: java -cp ".;.\lib\json-java.jar;.\src\main\java"
    // verifier.IAMRolePolicyVerifier
}

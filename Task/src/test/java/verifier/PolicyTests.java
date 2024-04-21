package verifier;

import org.junit.Test;

import verifier.IAMRolePolicyVerifier.InvalidPolicyConstruct;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class PolicyTests {

        @Test
        public void testFalsePolicies() throws InvalidPolicyConstruct {
                assertFalse(IAMRolePolicyVerifier.verifyIAMRolePolicy("JSON_files/false_policy.json"));
                assertFalse(IAMRolePolicyVerifier.verifyIAMRolePolicy("JSON_files/2false_policy.json"));
                assertFalse(IAMRolePolicyVerifier.verifyIAMRolePolicy("JSON_files/3false_policy.json"));
                assertFalse(IAMRolePolicyVerifier.verifyIAMRolePolicy("JSON_files/4false_policy.json"));
                assertFalse(IAMRolePolicyVerifier.verifyIAMRolePolicy("JSON_files/5false_policy.json"));
        }

        @Test
        public void testTruePolicies() throws InvalidPolicyConstruct {
                assertTrue(IAMRolePolicyVerifier.verifyIAMRolePolicy("JSON_files/true_policy.json"));
                assertTrue(IAMRolePolicyVerifier.verifyIAMRolePolicy("JSON_files/2true_policy.json"));
                assertTrue(IAMRolePolicyVerifier.verifyIAMRolePolicy("JSON_files/3true_policy.json"));
                assertTrue(IAMRolePolicyVerifier.verifyIAMRolePolicy("JSON_files/4true_policy.json"));
        }

        @Test
        public void testMissingVersionError() {
                try {
                        assertTrue(IAMRolePolicyVerifier.verifyIAMRolePolicy("JSON_files/5true_policy.json"));
                        IAMRolePolicyVerifier.verifyIAMRolePolicy("JSON_files/5true_policy.json");
                } catch (InvalidPolicyConstruct e) {
                        assertEquals("Given input does not implement AWS IAM policy correctly:Version' field missing",
                                        e.getMessage());
                }

        }

        @Test
        public void testMissingStatmentError() {
                try {
                        assertTrue(IAMRolePolicyVerifier.verifyIAMRolePolicy("JSON_files/10true_policy.json"));
                        IAMRolePolicyVerifier.verifyIAMRolePolicy("JSON_files/10true_policy.json");
                } catch (InvalidPolicyConstruct e) {
                        assertEquals("Given input does not implement AWS IAM policy correctly: 'Statement' field missing",
                                        e.getMessage());
                }
        }

        @Test
        public void testMissingEffect_or_ResourceError() {
                try {
                        assertTrue(IAMRolePolicyVerifier.verifyIAMRolePolicy("JSON_files/6true_policy.json"));
                        IAMRolePolicyVerifier.verifyIAMRolePolicy("JSON_files/6true_policy.json");
                } catch (InvalidPolicyConstruct e) {
                        assertEquals(
                                        "Given input does not implement AWS IAM policy correctly: 'Effect' or 'Resource' field missing in a statement",
                                        e.getMessage());
                }

                try {
                        assertTrue(IAMRolePolicyVerifier.verifyIAMRolePolicy("JSON_files/8true_policy.json"));
                        IAMRolePolicyVerifier.verifyIAMRolePolicy("JSON_files/8true_policy.json");
                } catch (InvalidPolicyConstruct e) {
                        assertEquals(
                                        "Given input does not implement AWS IAM policy correctly: 'Effect' or 'Resource' field missing in a statement",
                                        e.getMessage());
                }

                try {
                        assertTrue(IAMRolePolicyVerifier.verifyIAMRolePolicy("JSON_files/9true_policy.json"));
                        IAMRolePolicyVerifier.verifyIAMRolePolicy("JSON_files/9true_policy.json");
                } catch (InvalidPolicyConstruct e) {
                        assertEquals(
                                        "Given input does not implement AWS IAM policy correctly: 'Effect' or 'Resource' field missing in a statement",
                                        e.getMessage());
                }
        }

        @Test
        public void testMissingActionError() {
                try {
                        assertTrue(IAMRolePolicyVerifier.verifyIAMRolePolicy("JSON_files/7true_policy.json"));
                        IAMRolePolicyVerifier.verifyIAMRolePolicy("JSON_files/7true_policy.json");
                } catch (InvalidPolicyConstruct e) {
                        assertEquals(
                                        "Given input does not implement AWS IAM policy correctly: 'Effect' or 'Resource' field missing in a statement",
                                        e.getMessage());
                }
        }

}
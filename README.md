# OWNBURP
My own extensions for BurpSuite, free for you.
![Screenshot 2024-06-26 121146](https://github.com/Symbolexe/OWNBURP/assets/140549630/4dfb8543-a5a0-493f-be00-3c58a43c0226)
# step-by-step guide
## JWT Manipulation Tool
### Setup and Configuration:
#### Install the Extension:
1. Save the script as JWTManipulationTool.py.
2. Open Burp Suite and navigate to the "Extender" tab.
3. Click on the "Extensions" tab and then the "Add" button.
4. Select "Python" as the extension type and load JWTManipulationTool.py.
#### Using the Extension:
1. Navigate to the "JWT Manipulation" tab that appears.
2. You'll see the UI components for encoding, decoding, signing, and verifying JWTs.
3. Detailed Example for Each Functionality:
4. Decoding a JWT
#### Scenario:
You have intercepted a JWT in a request and want to decode it to see its contents.
#### Steps:
##### Intercept the Request:
- [x] Use Burp Suite's proxy to intercept a request containing a JWT.
- [x] For example, the JWT might be in the Authorization header or a request parameter.
- [x] Copy the JWT value (e.g., eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c).
##### Decode the JWT:
- [x] Navigate to the "JWT Manipulation" tab.
- [x] Paste the JWT into the "JWT" field.
- [x] Click the "Decode JWT" button.
- [x] The tool will display the decoded header, payload, and signature in a message box.
##### Analyze the Decoded JWT:
1. Review the decoded header and payload for sensitive information.
2. For example, the payload might contain user information such as {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}.
#### Encoding a New JWT
##### Scenario:
You want to create a new JWT with specific claims.
##### Steps:
##### Enter Header and Payload:
- [x] Navigate to the "JWT Manipulation" tab.
- [x] Enter the desired header in JSON format. For example: {"alg": "HS256", "typ": "JWT"}.
- [x] Enter the desired payload in JSON format. For example: {"sub": "1234567890", "name": "Jane Doe", "iat": 1516239022}.
##### Enter the Secret:
- [x] Enter the secret key that will be used to sign the JWT. For example: your-256-bit-secret.
##### Encode the JWT:
- [x] Click the "Encode JWT" button.
- [x] The tool will display the encoded JWT in a message box. For example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.4t9_JLZdx1Jd_wVtG9Gy_GcnmfsAsys_8Q1Z8uN9h6E.
##### Use the JWT:
1. Copy the encoded JWT and use it in your testing scenarios, such as modifying a request in Burp Suite.
2. Signing a JWT
##### Scenario:
You have a JWT with a modified payload and need to re-sign it.
##### Steps:
##### Modify the Payload:
- Decode the JWT using the steps described above.
- Modify the payload as needed. For example, change the name claim to {"sub": "1234567890", "name": "Jane Smith", "iat": 1516239022}.
- Encode the modified JWT without a signature.
##### Sign the JWT:
- [x] Navigate to the "JWT Manipulation" tab.
- [x] Paste the modified JWT into the "JWT" field.
- [x] Enter the secret key used for signing. For example: your-256-bit-secret.
- [x] Select the signing algorithm (e.g., HS256).
- [x] Click the "Sign JWT" button.

The tool will display the new signed JWT in a message box. For example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgU21pdGgiLCJpYXQiOjE1MTYyMzkwMjJ9.nGOW-U6x-SiJxFzR_ZKJPPv3XeJXmn5vEkVVi0VDibQ.
##### Use the JWT:
1. Copy the signed JWT and use it in your testing scenarios.
2. Verifying a JWT
##### Scenario:
You want to verify the validity of a JWT.
##### Steps:
1. Obtain the JWT:
- [x] Capture the JWT you want to verify from an intercepted request.
2. Verify the JWT:
- [x] Navigate to the "JWT Manipulation" tab.
- [x] Paste the JWT into the "JWT" field.
- [x] Enter the secret key used for signing. For example: your-256-bit-secret.
- [x] Select the signing algorithm (e.g., HS256).
- [x] Click the "Verify JWT" button.

The tool will display a message indicating whether the JWT is valid or invalid.
##### Using in Real-World Testing:
1. Intercept JWT Traffic:
- [x] Use Burp Suite to capture traffic containing JWTs.
2. Decode and Analyze:
- [x] Decode the JWT to inspect the claims and ensure they don’t contain sensitive information.
3. Modify and Test:
- [x] Modify the JWT payload to test authorization and authentication mechanisms.
4. Encode and Sign:
- [x] Create new JWTs with specific claims and sign them for testing purposes.
5. Verify Validity:
- [x] Ensure JWTs are correctly signed and valid before using them in requests.

## Hidden Parameters Detector
### Setup and Configuration:
#### Install the Extension:
1. Save the script as Hidden-Parameters.py.
2. Open Burp Suite and navigate to the "Extender" tab.
3. Click on the "Extensions" tab and then the "Add" button.
4. Select "Python" as the extension type and load Hidden-Parameters.py.
#### Using the Extension:
1. After loading, navigate to the "Hidden Params Detector" tab.
2. The tool will automatically start checking responses for hidden parameters.
#### Interpreting the Results:
- [x] The output will list detected hidden parameters in HTTP responses.
- [x] Parameters will be highlighted, and relevant issues will be logged.
- [x] Steps in Real-World Use:
#### Perform a normal web application scan using Burp Suite.
- Monitor the "Hidden Params Detector" tab for any detected hidden parameters.
- Investigate highlighted parameters to understand their purpose and potential security implications.

## Data Leak Prevention Tool
### Setup and Configuration:
#### Install the Extension:
1. Save the script as DataLeak.py.
2. Open Burp Suite and navigate to the "Extender" tab.
3. Click on the "Extensions" tab and then the "Add" button.
4. Select "Python" as the extension type and load DataLeak.py.
#### Using the Extension:
- [x] Navigate to the "Data Leak Prevention" tab that appears.
- [x] Optionally load additional patterns by clicking the "Load Patterns" button and selecting a file with regex patterns.
- [x] Perform web application testing as usual.
#### Interpreting the Results:
- The tool will analyze HTTP responses for predefined patterns (e.g., SSNs, credit card numbers).
- Detected data leaks will be displayed in the text area with the pattern that matched.
#### Steps in Real-World Use:
1. Configure the tool with additional patterns if necessary.
2. Perform web application testing.
3. Monitor the "Data Leak Prevention" tab for any detected data leaks.
4. Address any found issues by reviewing and fixing the code or configuration that leaks sensitive data.

## Common Real-World Workflow:
### Preparation:
- [x] Identify the target domains and applications.
- [x] Load all necessary extensions in Burp Suite.
### Scanning and Testing:
- [x] Use Burp Suite’s proxy to intercept and examine traffic.
- [x] Let the extensions run their checks in the background.
### Analysis:
- [x] Review the output from each extension tab.
- [x] Document and prioritize the issues based on severity.
### Remediation:
- [x] Fix identified issues in the application code or configuration.
- [x] Re-test to ensure issues are resolved.

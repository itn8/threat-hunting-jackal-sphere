# Threat Hunt - Operation "Jackal Spear"

![678a739712ab6108f29d2df6](https://github.com/user-attachments/assets/7d928597-57d8-46e7-826d-426f68920af9)



<h2>🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️</h2>

## Platforms and Languages Leveraged
- Microsoft Defender
- KQL (Kusto Query Language)

<h2>🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️</h2>

## Scenario
Threat Hunting Scenario: Operation Jackal Spear

Recent reports reveal a newly discovered Advanced Persistent Threat (APT) group known as "Jackal Spear," originating from South Africa and occasionally operating in Egypt. This group has been targeting large corporations using spear-phishing campaigns and credential stuffing attacks. By exploiting stolen credentials, they can gain access to systems with minimal login attempts.

Their primary targets are executives. Once they successfully compromise an account, they establish persistence by creating a secondary account on the same system with a similar username. This new account is then used to exfiltrate sensitive data while avoiding detection.

Your Mission:
Management has tasked you with identifying Indicators of Compromise (IoCs) related to this South African/Egyptian APT within our systems. If you find any IoCs, conduct a thorough investigation to track the attacker’s movements and piece together their tactics, techniques, and procedures (TTPs) until you’ve “solved the challenge.”

Final Step:
Once you’ve completed your hunt, present the “flag” to the community to claim your reward.

<h2>🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️</h2>

## Discovery Plan
- Investigate DeviceLogonEvents to obtain machine and malicious actor information
- Investigate other Device-category tables as necessary
  
<h2>🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️</h2>

## Objective Order
- a. Submit the name of the host within the Cyber Range that was compromised by the APT
- b. What is the public IP address of the attacker?
- c. How many login attempts did it take before the attacker successfully logged into the compromised machine?
- d. What account did the attacker create on the local machine?
- e. Name one of the files that was likely stolen by the attacker while logged into the new account?


<h2>🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️</h2>

## Steps Taken

1. Defender was chosen and narrowed to use an appropriate table. From the briefing, it’s known that credential stuffing may have been used, so investigating failed logins then then had a success is practical. Using DeviceLogonEvents, at least five failures are searched for before a success logged success to fit a basic brute force pattern.  

A plain search of the DeviceLogonEvents table first can be used to show all columns in the table.
### Query used:
```kql
DeviceLogonEvents
```
<br>

![Screenshot 2025-01-31 at 8 30 15 PM](https://github.com/user-attachments/assets/39bf1fe3-8d6f-4cad-a6c7-a802ff349299)

<br>
2. Next, entries are narrowed in the ActionType column, as the action type shows whether a login was a failure or success. There’s also another column that has a code number that equates to successes or failures but this information was deemed superfluous. 
The whole table is queried where there’s successes and failures, and summarized into counting each username (AccountName) that had a success and over 5 failures. We create columns “LogonFailed” and “SuccessfulLogin” as variables that show fail counts, and the timestamp for the successful login. “Project” is used to show desired columns listed in output. 

### Query used:
```kql
DeviceLogonEvents
| where ActionType == "LogonFailed" or ActionType == "LogonSuccess"
| summarize
	FailedAttempts = countif(ActionType == "LogonFailed"),
	SuccessfulLogin = maxif(Timestamp, ActionType == "LogonSuccess")
	by AccountName, RemoteIP
| where FailedAttempts > 5 and isnotempty(SuccessfulLogin)
| project AccountName, RemoteIP, FailedAttempts, SuccessfulLogin
```

<br>

<img width="1188" alt="Screenshot 2025-01-30 at 4 50 37 AM" src="https://github.com/user-attachments/assets/371088ed-ed8b-4a9b-ae91-43b971408a1c" />

<br>
3. With these results, and since it’s assumed the target is an executive account and not an admin account, “chadwicks” is deemed a likely AccountName match. The briefing mentions that the successful login was a play on the original executive’s AccountName, so other AccountName logins should be checked on the same machine. To find the machine name, the known attacker’s IP (RemoteIP) and AccountName are used to create a query. The machine name column is known here as DeviceName.

The DeviceLogonEvents table is searched for logins where an AccountName “chadwicks” was used, and where DeviceName is not empty.

### Query Used:
```kql
DeviceLogonEvents
| where AccountName == "chadwicks" and isnotempty(DeviceName)
```

<br>
![Screenshot 2025-02-01 at 11 00 41 PM](https://github.com/user-attachments/assets/641cc584-8911-4703-b1c3-8543b17e9e35)
<br>

This points to a device named corpnet-1-ny. (This is also the answer to the first hunt objective. Since the RemoteIP was obtained in the previous search, the attacker IP 102.37.140.95 is entered as the second objective. The RemoteIP can also be listed by projecting the column in the previous query. The next objective is to obtain a count of login attempts before the successful login. Since logins were also listed in a previous query in order to find a machine that fit brute force criteria, chadwicks is noted to have logged in 14 times before a success.)


4. With the device name, all logins into the machine can be scoured. The malicious actor made their name close to the original DeviceName, so it’s assumed the name was adjusted to not be radically different so as to not alert admins. All logins in the corpnet-1-ny machine are queried, and a manual search is performed to look through logins for an entry similar to chadwicks.

### Query used:
```kql
DeviceLogonEvents
| where DeviceName == "corpnet-1-ny"
```

<br>

<img width="1196" alt="Screenshot 2025-01-30 at 5 30 11 AM" src="https://github.com/user-attachments/assets/1c8f1223-ae81-4475-bb8e-579c8eece76f" />

<br>
The query could also be made to exclusively show unique login names:

### Query used:
```kql
DeviceLogonEvents 
| where DeviceName == "corpnet-1-ny" 
| summarize by AccountName
```

<br>
![Screenshot 2025-02-01 at 11 22 42 PM](https://github.com/user-attachments/assets/1cb23959-62e1-4317-a81c-f7c4f77e76db)
<br>

chadwick.s is determined to be the required AccountName. (This is the answer for objective d.)

5. The final objective required naming specific exfiltrated data. The task notes there are plural “files” stolen, hinting at a series of artifacts.

 <br>

 <br>
<h2>👾 👾 👾 👾 👾 👾 👾 👾 👾 👾 👾 👾 👾 👾 👾 👾 👾 👾 👾 👾</h2>
<details>
  <summary><h2>Unsuccessful Hunting Section. Click to Expand.</h2></summary>

  <br>

  The following are unsuccessful attempts to find the documents (please continue to after the 👾 👾 line to see the correct table query for the final objective).
  <br>
  In the list of schema/tables in Defender’s left bar, a search was performed for a relevant table. 
  Though Alerts and behavior tables could possibly show entries with a loss protection alert, no such info was found and better leads seemed isolated focused on the “Devices” schema.
  <br>
  The first standout table was DeviceFileEvents. The following are the most useful columns found. Query and hunting ideas follow each column name.
  <br>
  Timestamp - when event happened
  <br>

  DeviceID - ID of the machine 
  - not utilized, as DeviceName was sufficient no reason was present to suspect a cloned system name. 
  <br>

  DeviceName - Name of the Device 
  - All table searches would begin with <| where DeviceName == "corpnet-1-ny"> to narrow down to the target machine.
  <br>

  ActionType - What was being done (FileModified, FileCreated, FileDeleted, etc.) 
  - Search was performed to highlight modified files and deleted files performed after a file modification.

  <br>
  
  ![Screenshot 2025-02-01 at 10 13 36 PM](https://github.com/user-attachments/assets/49b73baa-459f-4522-9797-1dcf157db2e5)
  
  <br>
  FileName - Name of File 
  <br>

  FolderPath - Where the file is located 
  - Since the DeviceFileEvents table does not contain a AccountName column and joining to the LogonEvents wouldn’t be doable, folder paths queries to show files with the username directory in it can be used: <| where FolderPath contains "C:\\Users\\chadwick.s">
  <br>

  SHA256 - SHA256 signature 
  - Search for identical file signatures in files to see if something was renamed to something obscure or with a different extension before being sent.
  <br>
  
  ![Screenshot 2025-02-01 at 9 57 44 PM](https://github.com/user-attachments/assets/766cbe1c-2c00-41d7-a680-357bd4ae747c)
  
  <br>
  FileSize - Size of the file 
  - Column was clicked to arrange by file size. 
  <br>

  InitiatingProcessAccountName - What account carried out the action 
  - This column can be used as another workaround to search for files under a certain user <| where InitiatingProcessAccountName contains "chadwick.s">
  <br>

  InitiatingProcessFileName - Name of the application that executes the action on the file 
  - Used to narrow down actions executed by applications like Powershell and 7zip. Several suspicious documents were found, such as “gene_editing_papers.zip”, and files containing “crypto”, but did not work in zip form for the URL entry. The “InitiatingProcessCommandLine” column was       overlooked in the query results and record inspection which would have ended the search here as shown below. 
  <br>
  
  ![Screenshot 2025-02-01 at 10 01 26 PM](https://github.com/user-attachments/assets/48f7d47c-d1f6-4c5d-bd5c-ae9f3db8de29)
  
  <br>
  
  ![Screenshot 2025-02-01 at 10 04 35 PM](https://github.com/user-attachments/assets/e34c60ea-883d-488d-8fac-0b3afceb71aa)
  
  <br>
  RequestProtocol - Protocol used 
  - Search for transfer-supporting protocols
  <br>

  After lack of success, the DeviceNetworkEvents table was additionally tried, but no specifics for file names or transfer sizes were listed in its columns. We can find a connection event for the target machine as seen below, but the InitiatingProcessAccount was deemed a network service. 
  <br>
  
  ![Screenshot 2025-02-01 at 9 54 37 PM](https://github.com/user-attachments/assets/ecede297-e81d-4ea5-87ac-7a169540fdf8)
  
  <br>

</details>
<h2>👾 👾 👾 👾 👾 👾 👾 👾 👾 👾 👾 👾 👾 👾 👾 👾 👾 👾 👾 👾</h2>
 <br>

 <br>


The DeviceEvents table is investigated and performed another simple machine and user-based query.
<br>

### Query used:
```kql
DeviceEvents
| where DeviceName == "corpnet-1-ny"
| where InitiatingProcessAccountName contains "chadwick.s"
```

<br>
<br>

![Screenshot 2025-02-01 at 10 21 32 PM](https://github.com/user-attachments/assets/d1e4087b-bb94-46f6-bce9-09b52c33c175)

<br>
<br>
After the query, and investigating by process command line, expansion shows individual .pdf files compressed in the 7zip command. 
<br>
<br>

![Screenshot 2025-01-30 at 8 31 26 AM](https://github.com/user-attachments/assets/3f1371a4-de53-4c1d-a683-5ce00ec71fca)

<br>
<br>
Arranging by use of 7zip and FileName also lists each individual file.
<br>

### Query used:
```kql
DeviceEvents
| where DeviceName == "corpnet-1-ny"
| where InitiatingProcessAccountName contains "chadwick.s"
| where InitiatingProcessFileName contains "7z"
```

<br>

![Screenshot 2025-02-01 at 10 31 18 PM](https://github.com/user-attachments/assets/2c3bae53-b96e-43c1-9cbf-0a38b3408ee7)

<br>
<h2>🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️</h2>
<br>

## Summary of Findings
A malicious actor from a remote IP 102.37.140.95 performed a spear phishing attack to the target organization’s CEO, leading to information supporting a credential stuffing attack executed through targeted brute force logins.
The malactor succeeded in logging into a system “corpnet-1-ny” after 14 attempts with the username “chadwicks”.
To help avoid detection, the malactor created a new account to receive information from the original account. The new account had a name similar to the original “chadwicks” as “chadwick.s”. 
After desired files were obtained and zipped from the original AccountName, they were then zipped and prepared for exfiltration in the nefarious account. 
<br>
<h3>⚐⚐⚐</h3> Flag: f6952d6eef555ddd87aca66e56b91530222d6e318414816f3ba7cf5bf694bf0f <h3>⚐⚐⚐</h3>
<br>

<h2>🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️  🌍  🛡️</h2>
<br>

## Mitigation/Response
After the compromised device was created, an external response and recovery team were brought in to isolate the system in an airgapped network to determine any possible backdoor or C2 persistent tools. Upon discussion with the CISO, various holes were found in network security, and underutilization of Defender. A large gap in data exfiltration policy and automated response was highlighted. Since the targeted organization contains highly classified material, a heightened connection between its IPS and DLP policy was created. Additionally, a separation of duties was immediately enforced after the incident to not only avoid alternate account creation on highly confidential machines, but to add dual-user requirement regarding ACLs or any account edits leading through a process of request, approval and creation through multiple admin and superuser member visibility steps.
<br>

![679f4217cc005af6ea86b0d6](https://github.com/user-attachments/assets/ded80b33-274c-437d-87e5-e53a69cc78b6)






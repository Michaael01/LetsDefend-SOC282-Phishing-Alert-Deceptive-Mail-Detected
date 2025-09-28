# LetsDefend-SOC282-Phishing-Alert-Deceptive-Mail-Detected

##  What is Phishing Alert?

A phishing alert is a notification (from a SIEM, email security gateway, endpoint security tool, or threat intelligence system) that flags a suspicious email or activity which may be an attempt at phishing.

 👉 Phishing It is a social engineering attack where attackers try to trick a user (usually through email) into:
- Clicking a malicious link
- Downloading/opening a malicious attachment
- Giving up sensitive information (e.g., passwords, credit card numbers, or company data).

<img width="668" height="317" alt="image" src="https://github.com/user-attachments/assets/511954b1-9909-405b-a056-98a9d445198d" /> Image from Russ Michaels

## Alert

From the Alert as shown below, a suspicious link, malicous attachment or email requesting for a sensitive information was sent to Felix@letsdefend.io. The email originated from another domain with source address free@coffeeshooop.com that has the SMTP address 103.80.134.63. As a result of this, an alert was triggered by the SOC82 Phishing Alert rule. The device action is marked "ALLOWED", indicates no action was taken to block or prevent the mail.

This indicates that it is possible to have phishing activities taking place on the network. Therefore, urgent investigation is needed to detect the extent of the activities and remediate.

<img width="1878" height="455" alt="image" src="https://github.com/user-attachments/assets/c69cda7a-1743-4462-a50a-637e520a3dc2" />

## Alert Ownership

I took ownership of the ticket with Event ID 257 as the analyst investigating the ticket, for clear incident resolution, responsibilty, and accountability.
<img width="1470" height="833" alt="image" src="https://github.com/user-attachments/assets/7791fac1-1f27-4c56-a3ab-a6a816d50787" />

## Create Case

In order to ensure that the most critical issues are addressed without wasting time, I need to create a case and this will allow me to priortize incidents based on severity and potential impacts.
<img width="1061" height="614" alt="image" src="https://github.com/user-attachments/assets/93b3a181-180d-4d11-ad7f-700a6cd539e3" />

## Playbook

This will make incident response to be more consistence. The analyst will be able to respond to thrat in a consistence way.
<img width="1447" height="475" alt="image" src="https://github.com/user-attachments/assets/8b37482e-b2fe-427c-b285-9b4d3344db51" />

# Analysing with Playbook

## Parse Email
Parse email is a phishing alert playbook that systematically extract and analyze the technical details of the email (headers, body, attachments, URLs) to uncover hidden indicators of compromise. 

This can be done: 

- Mannually by Opening the raw email source like Outlook fil, properties, internet headers.
- Automatically with the use of online analyzers like MXToolbox Header Analyzer.

<img width="1125" height="652" alt="image" src="https://github.com/user-attachments/assets/cbe6273c-d936-455e-b1d0-dd998e005ef2" />


I proceeded to Email security in SIEM for more Analyst as suggested by playbook, I was able to the phishing alert

<img width="1910" height="665" alt="image" src="https://github.com/user-attachments/assets/5e870809-2869-4a4e-b80d-7eababf4e38b" />

I opened the suspected phishing email sent to Felix inbox

<img width="1787" height="825" alt="image" src="https://github.com/user-attachments/assets/1f99d49b-9340-43e0-8475-05436953cd0e" />

## The Playbook ( Parse Email for Artifacts)

- When was the Email sent?
  
  According to the Alert Event Time, the Enail was sent on May, 13, 2024, 09:22 AM
- what is the EMail's SMTP address?

  SMTP is known as Simple Mail Transfer Protocol. It is the protocol used to send emails between mail servers. According to the Alert, SMTP  Address 103.80.134.63 is the IP of the mail server that transmitted the phishing email into the environment.
   
- What is the sender address?

  The suspicious email is from free@coffeeshooop.com
  
- What is the recipient address?

  Felix@letsdefend.io
  
- Is the mail content suspicious?

  Yes. The password to the attachment says infected
  

## Analyze Attachments or URLs

The next step of the playbook is to analyse the urls or attachments.
- URLs show where the attacker wants the user to go.
- Attachments show what the attacker wants the user to run.
- Analyzing both is critical for confirming the phishing attempt.
- Understanding its impact for malware, virus, trojans, and ransomeware.
- Stopping it across the organization before its 


<img width="939" height="654" alt="image" src="https://github.com/user-attachments/assets/46823706-8c2a-409a-9003-6daac5a5795c" />

- Are there any attachment?

  yes. There is a zip file attachment named free-coffee at the botton of the suspected email
  

<img width="1407" height="873" alt="image" src="https://github.com/user-attachments/assets/5fd2e294-e702-4292-8283-555e37d9643b" />

## Analyze Attachments or URLs cont.

Since there is traces of attachment or url in the suspicious email. It is therefore importanc eto investigate further as suggested by playbook with the following tools:
- VirusTotal
- AnyRun
- URLHouse
- URLScan
- HybridAnalysis
<img width="1379" height="685" alt="image" src="https://github.com/user-attachments/assets/0c8f99ca-59b0-41d7-8d3d-0760ca35ef69" />

## VirusTotal

Here I used the SMTP IP address of the email sender to investigate the SIEM alert. 

- SMTP IP: 103.80.134.63

From the VirusTotal output, I can see that the IP address 6/95 securitz vendors flagged the IP address as malicious.
- AlphaSOC reported it as Suspicious
- G-Data and AlphaMoutain.ai reported it as Phishing
- CyRadar reported it as malicious
<img width="1666" height="761" alt="image" src="https://github.com/user-attachments/assets/fa03722b-043e-414b-8804-7a75e90d4132" />

## URLScan

I pasted the file url https://download.cyberlearn.academy/download/download?url=https://files-ld.s3.us-east-2.amazonaws.com/59cbd215-76ea-434d-93ca-4d6aec3bac98-free-coffee.zip to URLSCAN. The shoking findings is that the url has been scanned for about 532 time on urlscan.io. 
- The domain download.cyberlearn.academy resolved to IP 104.21.11.167, sitting behind Cloudflare’s network-
- The scanned URL points to a download request for a .zip file: free-coffee.zip hosted via AWS S3.
- The site performed 3 HTTP transactions, contacted 2 IPs in 2 countries, and used HTTPS / TLS (certificate valid until December 5, 2025).
According to findings, the urlscan did not assign a defifitive malicious classification but behavior is highly suspicious.
<img width="1209" height="843" alt="image" src="https://github.com/user-attachments/assets/4c1f6324-7be9-4dc3-816a-32237bd7e75d" />
<img width="564" height="520" alt="image" src="https://github.com/user-attachments/assets/001bb3f0-dd3c-4af7-86f5-562f03a24660" />

## HybridAnalysis
I pasted the url link on the hybridanalysis web page and I can see that the ulr has been flaged a suspicious. 
<img width="1060" height="1014" alt="image" src="https://github.com/user-attachments/assets/cfaad237-f6e6-4f8e-af50-ccc8c62e8816" />

I went further to check the suspicious indicators and I found two indicators
1. General: GETs files from a webserver.
- The traffic shows a legitimate HTTPS request from Microsoft-CryptoAPI/6.1 to download a root certificate file (rootg2.cer) from Amazon Trust’s certificate distribution host (crt.rootg2.amazontrust.com).

- The server responded with HTTP/1.1 200 OK, delivering a small binary file (1,145 bytes) — consistent with a certificate chain fetch.

- Headers such as x-amz-server-side-encryption: AES256 and X-Cache: Hit from cloudfront indicate the file is stored in Amazon S3 and served via CloudFront CDN, standard for certificate providers.

- Overall, this traffic is benign and expected system behavior: Windows automatically retrieving trusted root certificates to validate SSL/TLS connections, not a phishing or malware indicator.

2. Network Realted: Suspicous domain "cyberlearn.academy" detected. The att&ck ID as explained in MITRE ATT&CK https://hybrid-analysis.com/sample/6821699c050130aaaf05bd19/mitre

Based on my findings from VirusTotal and HybridAnalysis, I will therefore accept that the URL or attachment is suspicous and malicous. 

<img width="878" height="770" alt="image" src="https://github.com/user-attachments/assets/64c37818-d44f-4406-aa3a-d66a6042f2cc" />

## Artifacts — LetsDefend SOC282 Phishing Alert (EventID: 257)

- Sender Email: free@coffeeshooop.com – suspicious domain with typo-squatting pattern.

- Recipient Email: Felix@letsdefend.io – targeted internal user.

- SMTP IP Address: 103.80.134.63 – flagged as malicious/suspicious by multiple security vendors.

- Email Subject: “Free Coffee Voucher” – classic phishing lure using social engineering.

- Attachment: free-coffee.zip – compressed file likely containing malware.

- Suspicious URL: download.cyberlearn.academy/.../free-coffee.zip – repeatedly scanned on URLScan (532 times).

- Resolved IP: 104.21.11.167 – hosted behind Cloudflare, linked to suspicious domain.

- HybridAnalysis Finding: Domain cyberlearn.academy flagged as suspicious; potential phishing infrastructure.

- VirusTotal Finding: SMTP IP 103.80.134.63 marked as phishing/malicious by AlphaSOC, G-Data, AlphaMountain.ai, and CyRadar.

- Benign Traffic Note: Certificate fetch from crt.rootg2.amazontrust.com observed — normal Windows behavior, not malicious.

## Checking If Mail Delivered to User

<img width="905" height="407" alt="image" src="https://github.com/user-attachments/assets/6adb5bdf-77dc-4050-8ade-345e5a0ad124" />

I can simply determine by looking at the device action of the alert, which tells me that the email was delivered to either the inbox of Felix

<img width="1065" height="596" alt="image" src="https://github.com/user-attachments/assets/fb2f66cf-f440-4ddc-9979-11b72d43ed87" />

## Delete Email From Recipient!

The next action suggested by playbook is to delete the email. I therefore, clicked on delete to remove the email.

<img width="840" height="343" alt="image" src="https://github.com/user-attachments/assets/deab2859-1c8d-474a-9a95-f387d23c09eb" />

## Check If Someone Opened the Malicios File/URL

<img width="816" height="465" alt="image" src="https://github.com/user-attachments/assets/25cac06b-9157-4e6b-a231-510bed16689e" />

🔹 What is C2 (Command and Control)?

C2 stands for Command and Control. It’s the infrastructure (usually servers or domains) used by attackers to maintain communication with malware on an infected machine.

Once a user opens a malicious file or URL, the malware often tries to connect to its C2 server to:

- Receive further instructions (download payloads, execute commands).

- Exfiltrate stolen data (credentials, files).

- Maintain persistence inside the victim’s environment.

<img width="1854" height="412" alt="image" src="https://github.com/user-attachments/assets/18a7557b-1159-4e8a-a5e2-b64645f3bc2a" />

  The destination IP address based on the report from log management is 37.120.233.226. The process is known to be Coffee.exe that actually connected to C2 address. The phishing email was opened and the malware coffee.exe executed successfully on host 172.16.20.151

<img width="1753" height="590" alt="image" src="https://github.com/user-attachments/assets/10da630a-8cdc-4d48-8023-eabee1aa77c9" />

## Containment

I went to the EDR page and therefore contained the user machine and as you can see, coffee.exe was processed with the explorer and executed from the cmd.

<img width="1819" height="912" alt="image" src="https://github.com/user-attachments/assets/9df3fa08-c717-40a3-b3d4-95793e810c6f" />

- Terminal History: checking the Terminal history, I found out that the attacker ran various commands on Felix machine

<img width="1137" height="723" alt="image" src="https://github.com/user-attachments/assets/3d7ccaab-22e8-4cce-aa69-68294db3cf92" />

- Browser History: I can also see the Domain/url actions which correspond with my research on URLSCAN

<img width="1509" height="573" alt="image" src="https://github.com/user-attachments/assets/df6c13ed-6ede-485c-a329-9eab881ed230" />

- Network Action: I can see the attacked Ip interacting with Felix machine on May 13 2024 13:00:39 and on May 13 2024 13:01:48

<img width="1317" height="773" alt="image" src="https://github.com/user-attachments/assets/5080b4c6-b0ed-4580-af86-a36414f632d1" />

I can further say that it is clear that malicious activities took place, Felix credentials may have been compromised, sensitive informations may have been stolen, the machine also may have been affected. Therefore, I find it justifiable to contain Felix machine.

## Adding My Artifacts

<img width="841" height="679" alt="image" src="https://github.com/user-attachments/assets/7ec71205-8ff0-4dca-9a1c-4636181fad50" />

# Analysis Note – LetsDefend SOC282 Phishing Alert (EventID: 257)

A phishing email titled “Free Coffee Voucher” was sent to Felix@letsdefend.io from free@coffeeshooop.com.

The SMTP IP 103.80.134.63 and sender domain were flagged as malicious.

The email carried free-coffee.zip, which executed as coffee.exe.

The malware attempted outbound communication with C2 server 37.120.233.226:3451.

Logs confirmed execution from host 172.16.20.151, proving user interaction.

Impact: potential credential theft and system compromise through C2 communication.

Actions: host isolation, phishing email removal, IOC documentation, and blocking.

Recommendations: forensic analysis, credential reset, network monitoring, and phishing awareness training.

<img width="803" height="676" alt="image" src="https://github.com/user-attachments/assets/84f761a2-b176-4d17-bf5b-a4af5989290c" />

## Finished Playbook

<img width="759" height="667" alt="image" src="https://github.com/user-attachments/assets/76fd744b-8bef-48e2-bf38-79e5741a313c" />
<img width="711" height="691" alt="image" src="https://github.com/user-attachments/assets/0838ad43-083d-4508-831f-c43e0882f42c" />


## Closing Ticket

- Note – SOC282 Phishing Alert (EventID: 257)
The phishing email with malicious attachment (free-coffee.zip → coffee.exe) was confirmed to establish C2 communication from host 172.16.20.151. The endpoint was isolated, credentials reset, and malicious domains/IPs blocked. Phishing email removed from inbox. Incident contained, no further suspicious activity observed. Ticket alert closed as true positive. ✅

<img width="1880" height="600" alt="image" src="https://github.com/user-attachments/assets/81f0f82d-5519-447a-8415-b5a658014b7d" />

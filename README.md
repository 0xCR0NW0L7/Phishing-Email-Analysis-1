# Phishing Email Analysis 1

### **Instructions:**

- You are a SOC Analyst at Mighty Solutions, Inc. Dana Derringer, an account executive, noticed a warning email in her inbox claiming her online access has been disabled. However, she is still able to access her online business platforms and inbox. She forwarded the email to the security team's phishing mailbox for review.
- Using what you've learned within this domain, perform a detailed email analysis on the `challenge1.eml` file to answer the report questions below.

### **Challenge Questions:**

**Challenge File**

- `01_Phishing_Analysis/Challenges/challenge1.eml`

Q1 Based on the contents of the email header, what is the full date and time of the email delivery?

- `Tue, 31 Oct 2023 10:10:04 -0900`

Q2 What is the subject of the email?

- `Your account has been flagged for unusal activity`

Q3 Who was the email sent to?

- `dderringer@mighty-solutions.net`

Q4 Based on the sender's display name, who does the email claim to be from?

- `Microsoft Outlook Support Team`

Q5 What is the sender's email address?

- `social201511138@social.helwan.edu.eg`

Q6 What email address is used for receiving bounced emails?

- `social201511138@social.helwan.edu.eg`

Q7 What is the IP address of the sender's email server?

- `40.107.22.60`

Q8 What is the resolved hostname of the sender's IP address?

- `mail-am6eur05on2060.outbound.protection.outlook.com`

Q9 What corporation owns the sender's IP address?

- `Microsoft Corporation`

Q10 What was the result of the SPF check?

- `The SPF authentication was passed`

Q11 What is the full SPF record of the sender's domain?

- `spf=pass (sender IP is 40.107.22.60) smtp.mailfrom=social.helwan.edu.eg;`

```bash
nslookup -type=TXT helwan.edu.eg
Server:  UnKnown
Address:  fe80::866e:bcff:fef2:7101

Non-authoritative answer:
helwan.edu.eg   text =    "MS=ms29792596"
helwan.edu.eg   text =    "v=spf1 include:spf.protection.outlook.com -all"
helwan.edu.eg   nameserver = FRCU.EUN.eg
```

Q12 What is email's Message ID?

- `JMrByPl2c3HBo8SctKnJ5C5Gp64sPSSWk76p4sjQ@s6`

Q13 What type of encoding was used to transfer the email body content?

- `Base64 encoding was used to transfer the email body content`

Q14 In defanged format, what is the second URL extracted from the email?

- `hxxps[://]0[.]232[.]205[.]92[.]host[.]secureserver[.]net/lclbluewin08812/`

Q15 Perform a VirusTotal scan on the URL. What verdict did Fortinet assign to it?

- `Phishing`

Q16 [Yes or No] - After your analysis, is this email genuine?

- `No`

### Challenge URL

- [https://challenges.malwarecube.com/#/c/074e4448-e8d7-4122-86f2-36a4d7b2a18b](https://challenges.malwarecube.com/#/c/074e4448-e8d7-4122-86f2-36a4d7b2a18b)

---

## Challenge 1 Report

![Screenshot 1](https://raw.githubusercontent.com/0xCR0NW0L7/Phishing-Email-Analysis-1/main/img/image.png)

## Headers

| **Header** | **Value** |
| --- | --- |
| Date | `Tue, 31 Oct 2023 10:10:04 -0900` |
| Subject | `Your account has been flagged for unusual activity` |
| From | `social201511138@social.helwan.edu.eg` |
| To | `dderringer@mighty-solutions.net` |
| Reply-To | NA |
| Return-Path | `social201511138@social.helwan.edu.eg` |
| Sender IP | `40.107.22.60` |
| Resolved Host | `mail-am6eur05on2060.outbound.protection.outlook.com` |
| Message-ID | `JMrByPl2c3HBo8SctKnJ5C5Gp64sPSSWk76p4sjQ@s6` |

## URLs

1. `hxxps[://]0[.]232[.]205[.]92[.]host[.]secureserver[.]net/lclbluewin08812/`

## Attachments

| **File Name** | NA |
| --- | --- |
| **MD5** | NA |
| **SHA1** | NA |
| **SHA256** | NA |

## Description

This email is a **phishing attempt claiming to be from Microsoft Outlook Support Team**, warning the recipient about alleged unusual activity and requesting account re-verification. The email creates urgency to trick the user into clicking the embedded link.

**The analysis includes:**

- Verification of **email authentication mechanisms** (SPF, DKIM, DMARC).
- Examination of **URLs** embedded in the email for malicious content.
- Assessment of **attachments** (none present).

## Artifact Analysis

- **Sender Analysis:**
    - SPF = Pass, DKIM = Pass, DMARC = Best Guess → **domain misuse detected**
    - From domain mismatch: `helwan.edu.eg` pretending as Outlook Support
- **URL Analysis:**
    - Primary phishing page hosted on `secureserver.net` subdomain
    - VirusTotal flagged the URL as malicious/phishing
    - Likely compromised hosting used for phishing
- **Attachment Analysis:**
    - No attachments present

## Verdict

- Email **is phishing**, impersonating Microsoft Outlook
- Embedded URL flagged as malicious
- User should not click any links

## Defense Actions

- Block sender domain and listed IPs/URLs
- Alert and educate users about phishing attempts
- Hunt in logs for clicks on phishing URLs
- Share IoCs (IPs, domains, URLs) with the CTI platform

## Screenshots

---

1. Reverse IP Lookup

![Challenge 1 Screenshot](https://raw.githubusercontent.com/0xCR0NW0L7/Phishing-Email-Analysis-1/main/img/image%201.png)


1. VirusTotal Checks

![Screenshot 2](https://raw.githubusercontent.com/0xCR0NW0L7/Phishing-Email-Analysis-1/main/img/image%202.png)

1. URLscan.io check

![Screenshot 3](https://raw.githubusercontent.com/0xCR0NW0L7/Phishing-Email-Analysis-1/main/img/image%203.png)

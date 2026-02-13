# YARA

# Objective

The objective of this lab was to understand and apply YARA for malware detection and threat hunting within the TryHackMe YARA room. The lab focused on learning how YARA rules are structured, how pattern matching is used to identify malicious files, and how custom rules can be created to detect specific malware characteristics. Through this exercise, I practiced developing detection logic, analyzing file artifacts, and applying signature-based detection techniques similar to those used in SOC environments and threat intelligence operations.

# Tools Used

YARA (Pattern Matching Engine)

Linux Command Line Interface (CLI)

Sample Malware Files / Suspicious Artifacts

Loki, yarGen, Valhalla, VirusTotal


# Lab Focus Areas (YARA – Malware Detection & Threat Hunting)

# Understanding YARA Rule Structure

* Rule components: Rule identifiers, Strings (text, hex, regex patterns), and Conditions (logical operators, boolean expressions)

* Metadata usage for documentation and classification

# Malware Identification & File Analysis

* Scanning suspicious files using YARA

* Identifying malicious artifacts based on rule matches

* Differentiating between benign and malicious file pattern

# Threat Hunting Applications

* Using YARA to search directories for malicious indicators

* Applying rule-based detection to large sets of files

* Supporting incident investigations with file-level analysis

# Skills Learned

# YARA Rule Development & Custom Detection Creation
* Developed the ability to write structured YARA rules to detect malware families and suspicious file characteristics.
# Signature-Based Malware Detection
* Strengthened understanding of how pattern matching is used to identify known threats within files and memory artifacts.
# Threat Hunting Techniques
* Used YARA as a hunting tool to proactively scan systems for malicious artifacts
# Analytical Thinking in Malware Analysis
* Applied logical operators and structured conditions to improve detection accuracy and reduce false positives.

# Steps


# Phase 1: Automated Threat Detection with Loki
My initial step was to deploy Loki, an open-source IOC scanner, to automate the detection of known malicious indicators within the suspicious-files directory.

# Step 1.1: Scanning File 1
I executed the Loki scanner against the directory containing file1 (ind3x.php).
* Command: python ../../tools/Loki/loki.py -p .

<img width="780" height="307" alt="image" src="https://github.com/user-attachments/assets/83ffdd5c-b90f-4bdb-ab5c-c6a6fa311ce1" />

* Findings: Loki flagged the file as Suspicious with a score of 70.




* Signature Match: The file matched the YARA rule webshell_metaslsoft.



* Classification: Loki classified this object specifically as a Web Shell.
  
* Artifact Analysis: By inspecting the output, I confirmed the specific string that triggered the alert was Str1. Further analysis of the file header and comments revealed the tool was b374k shell version 2.2.


<img width="780" height="585" alt="image" src="https://github.com/user-attachments/assets/2ae9eed1-8519-4c83-9582-83aea2e7fadc" />

<img width="780" height="580" alt="image" src="https://github.com/user-attachments/assets/d91baf09-643b-4b6c-9b87-0cbfa3935259" />


# Step 1.2: Scanning File 2
I proceeded to scan file2 (1ndex.php) using the same parameters.

<img width="780" height="580" alt="image" src="https://github.com/user-attachments/assets/411482a3-0fa2-45ec-b4e6-575d6e3dce78" />


* Findings: The system returned a "clean" result. Loki did not detect any suspicious or malicious evidence based on its default signature set.



* Conclusion: This indicated a potential false negative or a newer variant of malware not yet covered by the standard signature base, requiring manual intervention.

# Phase 2: Manual Analysis & Custom Signature Generation
To address the detection gap for file2, I moved to manual inspection and custom rule generation.

# Step 2.1: Manual File Inspection
I manually inspected file2 using the nano editor to understand its behavior and origin.
-Observation: The file header clearly displayed detection evasion attempts but identified itself as b374k shell version 3.2.3.


<img width="780" height="674" alt="image" src="https://github.com/user-attachments/assets/2ee3de1f-2f14-4329-b7d1-bafed1bf24e0" />


* Assessment: Despite being a known tool, the version difference (3.2.3 vs. the 2.2 found in file1) likely caused the signature mismatch.
# Step 2.2: Generating Rules with yarGen
To automate the creation of a detection rule for this specific variant, I utilized yarGen, a tool that generates YARA rules by identifying unique strings in a file while filtering out common legitimate strings.
* Action: I generated a rule specifically for file2.

<img width="780" height="152" alt="image" src="https://github.com/user-attachments/assets/29c93240-4d8f-482a-8820-de7fb669276c" />

<img width="780" height="185" alt="image" src="https://github.com/user-attachments/assets/cadeccc6-5f05-441d-9b72-703f6a1c6dfc" />


<img width="780" height="669" alt="image" src="https://github.com/user-attachments/assets/d236b5ea-05a8-46ae-92e8-9f9185ff45e5" />


* Rule Analysis: Inspecting the generated file2.yar, I noted that It relied on 20 specific strings to identify the file. It included a specific variable named Zepto in the string mal of How It set a file size condition, specifying the file must be < 700KB


<img width="780" height="109" alt="image" src="https://github.com/user-attachments/assets/1f7727e6-26d3-4946-88a8-e789d4968dc3" />



# Step 2.3: Validation and Integration
Before deploying the rule, I tested its efficacy.
* Test Command: yara file2.yar file2/1ndex.php
* Result: The rule successfully flagged file2.
* Integration: I copied the newly created rule into Loki's signature database (/loki/signature-base/yara/).
* Re-Scanning: I re-ran the Loki scanner against file2.
* Outcome: Loki now successfully detected file2 as malicious, validating the custom signature.

# Phase 3: Threat Intelligence & Attribution (Valhalla)
To gain broader context on the identified threats, I leveraged Valhalla, a YARA rule feed and search engine by Nextron Systems.
# Step 3.1: File 1 Intelligence (SHA256 Analysis) 
I submitted the SHA256 hash of file1 to Valhalla.

<img width="780" height="582" alt="image" src="https://github.com/user-attachments/assets/d733e9e9-3b27-410b-8d55-657bc46d4703" />




* Attribution: The analysis confirmed the file is attributed to an APT (Advanced Persistent Threat) group.

<img width="780" height="115" alt="image" src="https://github.com/user-attachments/assets/a7979f37-1b66-45f6-94ef-444cfd3cfaad" />


* Validation: This confirmed the severity of the initial Loki detection.
Step 3.2: File 2 Intelligence
I performed a similar lookup for the SHA256 hash of file2.


<img width="780" height="572" alt="image" src="https://github.com/user-attachments/assets/e28cf23e-c7ca-4a88-9d69-b3d5972598c2" />



* Existing Rules: Valhalla revealed an existing rule named Webshell_b374k_rule1 that covers this file.



* Source: The signature match originated from the THOR APT Scanner.


* VirusTotal Correlation:
A cross-reference with VirusTotal showed that not all antivirus engines detected this file as malicious, highlighting the importance of specialized YARA rules. The file was also recorded with an .EXE extension in the wild, suggesting it is sometimes dropped as an executable rather than a PHP script.

<img width="780" height="232" alt="image" src="https://github.com/user-attachments/assets/0ce221a9-e939-4ad4-8d53-736e39459aae" />


* Library Identification: The analysis confirmed the web shell utilizes the Zepto JavaScript library.



# Step 3.3: Gap Analysis
Finally, I checked if the effective rule (Webshell_b374k_rule1) was present in the default Loki YARA set I used in Phase signatures 1. 
-Finding: The rule was not present in the default set because there was no response. 

![Uploading image.png…]()

 
# Summary: 
I successfully authored and deployed a functional YARA rule to patch a detection gap in the Loki scanner. In this project, I demonstrated the limitations of automated detection by identifying a b374k web shell variant that bypassed the Loki scanner. I manually analyzed the malware, generated a custom YARA rule using yarGen to bridge the detection gap, and validated the threat against Valhalla intelligence. This exercise highlights my ability to engineer custom detection logic and attribute threats when standard  fail


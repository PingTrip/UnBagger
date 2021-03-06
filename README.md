# UnBagger
### Description
UnBagger is an analysis tool for quickly extracting IOCs from Xbagging Office Exploit (aka Bartallex) malware samples. Its intent is not to provide a comprehensive behavior report but rather to aid an IR team in rapidly determining if the infection chain completed.

### Usage
1. Use your tool of choice to extract the embedded object from the Office document.
    ```
    OfficeMalScanner.exe sample.docx inflate
    ```
2. Execute UnBagger, passing the filename of the extracted object as an argument.
    ```
    python unbagger.py oleObject1.bin 
    ```
3. Output includes the secondary payload URLs and the XOR key to decrypt the payloads.
    ```
    - Parsing VBS file...
    
    - Locating de-obfuscation function...
        + Found Y9Ocx6cw() as the de-obfuscation function...
    
    - De-obfuscating strings...

    - Secondary payload loactions: 
        hxxp://185.189.14[.]193/odg.jd
        hxxp://indigopoolandoutdoor[.]com/log.pkp
    
    - Extracted XOR key for payloads: 115
    ```
### References 
- ProofPoint [The Cybercrime Economics of Malicious Macros](https://www.proofpoint.com/sites/default/files/documents/bnt_download/pp-macroeconomics-rr.pdf)
- Didier Stevens [MalDoc Anaysis](https://blog.didierstevens.com/2015/12/28/maldoc-get-range/)

### Changes
#### v1.5 2017-03-21
 - I've removed the 'noise filter' routine due to a tactic shift in recent samples related to the "noise" added to the VB code. Specifically, bogus variable assignments now include nested references, making them much more difficult to detect. For example:
    ```
    PzeIxr=“92"-"22"
    RYPJ9Avt=PzeIxr+EX
    ```
- I expanded the coverage of de-obfuscated strings by creating a table of variable name/value pairs to handle both situations where the de-obfuscation key is passed directly or by reference
    ```
    deob("ObfuscatedString","KeyValue")
    deob("ObfuscatedString",VariableWithKeyValue)
    ```

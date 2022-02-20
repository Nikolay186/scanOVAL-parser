# scanOVAL-parser
## How to run:
1. Build the program with `cargo build --release`
2. Place `report.html`, `capec.csv`, `cwe.csv` and `vulnlist.csv` with executable where:
  report.html - exported report from ScanOVAL;
  vulnlist.csv - semicolon-separated file with bdu, cve(or other specs id) and cwe ids;
  cwe.csv - comma-separated file with cwe id and capec ids related to it;
  capec.csv - comma-separated file with capec id and it's likelihood of attack.
3. Run the executable
Output will be written to `result.csv` which placed in the same directory as the executable. 
This file contains following tab-separated columns:
  BDU - BDU id of the vulnerability;
  CVE - CVE id of the vulnerability;
  CWE - CWE id of the vulnerability;
  High - CAPEC ids with the high likelihood of attack;
  Medium - CAPEC ids with the medium likelihood of attack;
  Low - CAPEC ids with the low likelihood of attack;
  Zero - CAPEC ids with the zero likelihood of attack;

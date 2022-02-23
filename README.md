# scanOVAL-parser
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/Nikolay186/scanOVAL-parser?color=green&label=Latest%20release&style=plastic)](https://github.com/Nikolay186/scanOVAL-parser/releases/latest)
## How to run:
1. Build the program with `cargo build --release` or download executable for your system from [releases page](https://github.com/Nikolay186/scanOVAL-parser/releases)
2. Place `report.html`, `capec.csv`, `cwe.csv` and `vulnlist.csv`(can be found [here](https://drive.google.com/file/d/1qpauKzEZRhWc57zmvnfVhePOEsOAUpCD/view?usp=sharing)) with executable where:
  
    `report.html` - exported report from ScanOVAL;
    
    `vulnlist.csv` - semicolon-separated file with bdu, cve(or other specs id) and cwe ids;
    
    `cwe.csv` - comma-separated file with cwe id and capec ids related to it;
    
    `capec.csv` - comma-separated file with capec id and it's likelihood of attack.
  
3. Run the executable
Output will be written to `result.csv` which placed in the same directory as the executable. 
This file contains following tab-separated columns:

    `BDU` - BDU id of the vulnerability;
  
    `CVE` - CVE id of the vulnerability;
  
    `CWE` - CWE id of the vulnerability;
  
    `High` - CAPEC ids with the high likelihood of attack;
  
    `Medium` - CAPEC ids with the medium likelihood of attack;
  
    `Low` - CAPEC ids with the low likelihood of attack;
  
    `Zero` - CAPEC ids with the zero likelihood of attack;

## Found a bug?
If you've faced a bug, please report it in issues. Provide the following information:
  1. Report file
  2. Csv files
  3. Given error

The code has almost no error handling now(it'll be added later) so all the errors displayed in console/terminal.

## Contributing
The project welcomes contributions and suggestions. If you have ones, create an issue or open a pull request.

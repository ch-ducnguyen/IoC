# IoC
CrowdStrike IoC Uploader

# Installation
```bash
git clone https://github.com/ch-ducnguyen/IoC.git \ 
cd Ioc \ 
python3 -m pip install -r requirements.txt 
```

# Usage 
```bash
usage: IoC.py [-h] -C CSV -t TAG [-G] [-s SEVERITY] [-p PLATFORM] [-H HOST_GROUP] [-c COMMENT] [-d DESCRIPTION] [-a ACTION]

options:
  -h, --help            show this help message and exit
  -C CSV, --csv CSV     Path to csv file
  -t TAG, --tag TAG     Tag for indicator. Use "," as delimeter. Example TAG1,TAG2,TAG3
  -G, --apply-global    Apply globally (Default = False)
  -s SEVERITY, --severity SEVERITY
                        Indicator severity (Default = Informational)
  -p PLATFORM, --platform PLATFORM
                        Platform name. Use "," as delimeter. Example Windows,Mac,Linux
  -H HOST_GROUP, --host-group HOST_GROUP
                        Host group. Use "," as delimeter. If --apply-global is set this will be empty
  -c COMMENT, --comment COMMENT
                        Comment for indicator (Default is empty)
  -d DESCRIPTION, --description DESCRIPTION
                        Description for indicator (Default is empty)
  -a ACTION, --action ACTION
                        Action for indicator (Default is detect). Valid value : 'detect','block','allow','no_action'
```


Example Usage : 
```bash
python3 IoC.py -C test.csv -t TAG -G -d "some description" 
```

If -G or --apply-global is used, host group will be empty. Use --host-group for specific host group
Example: 

```bash
python3 IoC.py -C test.csv -t TAG -H Windows
```

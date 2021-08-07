# apk-hunter
Android Application Vulnerability Analysis And Android Pentest Tool Built In Ruby

[![forthebadge](https://forthebadge.com/images/badges/made-with-ruby.svg)](https://forthebadge.com)

# Installation
```
$ git clone https://github.com/krishpranav/apk-hunter
$ cd apk-hunter
$ ./install.sh
$ ruby apkhunter.rb
```

# Usage:
```
Usage: ruby apkhunter.rb [APK]
Command
-a, --apk : Analysis android APK file.
 + APK Analysis
    apkhunter -a 123.apk[apk file]
    apkhunter --apk 123.apk aaa.apk test.apk hwul.apk
-p, --pentest : Penetration testing Device
 + Pentest Android
    apkhunter -p device[device code]
    apkhunter --pentest device
-v, --version : Show this droid-hunter version
-h, --help : Show help page
```

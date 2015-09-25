# prisma
Command Line STDOUT Colorizer

# Requirements

- [colorama](https://pypi.python.org/pypi/colorama)

# Usage
Prisma works on all platforms, Linux, OSX and Windows. 
Just pipe command line output to prisma.py

```
cat /var/log/syslog | python ./prisma.py
```

or make it executable and place it in a binary folder in order to use it anywhere you want
 
```
chmod +x ./prisma.py
sudo cp prisma.py /usr/local/bin
cat /var/log/syslog | prisma.py
```

# Screenshots

System log file

![Log File Output Colorized](./screens/screen1.png)

Firewall Log

![Log File Output Colorized](./screens/screen2.png)

Strings output on malware sample 

![Log File Output Colorized](./screens/screen3.png)

Tcpdump output

![Log File Output Colorized](./screens/screen4.png)

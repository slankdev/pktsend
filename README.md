
# pktsend

Tiny packet sender. User can craft IP packet flexibly.
I assume that this tool is used with shell-scripts.
It is easy to extend (ex. net protocol fields). If you neet to support
new feature to this software, please tell me that. (author info is below)


## Install/Uninstall

```
$ git clone http://github.com/slankdev/pktsend
$ cd pktsend
$ make && sudo make install //install
$ sudo make Uninstall // uninstall
```


## Options

```
$ pktsend -h
USAGE: ./pktsend [OPTION]

Basic Option
    -i ifname                    interface name
    -w file                      write as pcap format
    -c count                     packet count
    -h                           show usage
    --version                    show version
    --verbose                    verbose output
    --hex                        print packet as hex

Option for Crafting Packet Binary
    --hsrc=11:22:33:44:55:66     src mac address
    --hdst=ff:ff:ff:ff:ff:ff     dst mac address
    --etype=0x0800               ethernet type
    --psrc=192.168.0.10          src ip address
    --pdst=192.168.0.1           dst ip address
    --proto=1                    ip protocol
```


## Execution Sample Scripts

```
#!/bin/bash

for ((i=0; i<10; i++)) do
	sudo pktsend --psrc=192.168.0.$i -i lo
done
```


## Author & Licence

This software is developed under the MIT Licence. please see LICENCE

Autor Infos
- Hiroki SHIROKURA
- slank.dev [at] gmail.com
- @slankdev (twitter)
- hiroki.shirokura (facebook)



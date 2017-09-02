# pktsend
Tiny packet sender. User can craft IP packet flexibly.

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


## Author & Licence

This software is developed under the MIT Licence. please see LICENCE

Autor Infos
- Hiroki SHIROKURA
- slank.dev [at] gmail.com
- @slankdev (twitter)
- hiroki.shirokura (facebook)



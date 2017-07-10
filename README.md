# Sniffer

A network sniffer written in python

## Installing / Getting started

Sniffer needs python3 

```shell
python sniffer.py
```

## Features

* Windows and linux support
* Saving captured packages to pcap file

## Configuration


```
A packet sniffer. Collect packets until ctrl+c pressed or after -t seconds

optional arguments:
  -h, --help            show this help message and exit
  -f FILENAME, --filename FILENAME
                        pcap file name (don't give extension)
  -nr, --noraw          No Raw mode, Stops printing raw packets
  -t TIME, --time TIME  Capture time in second
```




## Licensing

The code in this project is licensed under MIT license.
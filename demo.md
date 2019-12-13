# Demo
## Set-up
```
$ python3 netsim/network.py -p './network' --clean
$ python3 server.py
$ python3 client.py -u levente12 -p Ey3L0v3m@@thH^C
$ python3 client.py -u istvanist -p tEs$sor1t2
$ python3 client.py -u gabor@ait -p aitAITaitA1T
```
## Main functionality
* create directory: project (MKD)

```
$ MKD -n projects
```

* upload files: hw1.pdf and hw2.pdf to hw folder (UPL)

```
$ CWD -p hw
$ UPL -n hw1.pdf
$ UPL -n hw2.pdf
```

* delete file hw1.pdf (RMF)

```
$ RMF -f hw1.pdf
```

* move to projects folder (CWD)

```
$ CWD -p ../projects
```

* ask for the current folder (GWD)

```
$ GWD
```

* delete the projects folder (RMD)

```
$ RMD -n .
```

* move to the hw folder (CWD)

```
$ CWD -p hw
```

* list files in hw folder (LST) 

```
$ LST
```

* download hw3.pdf (DNL)

```
$ DNL -f hw3.pdf -d .
```

## Edge cases and attacks
* replay attack

```
$ python3 client.py -u levente12 -p Ey3L0v3m@@thH^C -a 1
```

* modification attack

```
$ python3 client.py -u levente12 -p Ey3L0v3m@@thH^C -a 2
```

* brute-force attack

```
$ python3 client.py -u levente12 -p 123456 
```

* impersonation attack

```
$ python3 client.py -u levente12 -p Ey3L0v3m@@thH^C 
$ CWD -p ../gabor@ait
```

* demonstrate new user login: 1) while session is active 2) after session ends

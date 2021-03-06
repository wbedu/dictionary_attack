password_cracker
----------------
brute force, offline, dictionary attack of shadow files

supports hashlib.sha512, hashlib.sha384, hashlib.sha256,hashlib.sha224, hashlib.sha1, hashlib.md5


##### How to run:

```bash
./password_cracker -w your_dictionary_file -s your_shadow_file
```

##Arguments
```bash
  -h, --help            show this help message and exit

  -s SHADOWFILE, --shadowfile SHADOWFILE
                        #Shadow file path

  -w WORDLIST, --wordlist WORDLIST
                        #wordlist file path

  -o OUTPUT, --output OUTPUT
                        #output file (default=passwords.txt)

  -t THREADCOUNT, --threadcount THREADCOUNT
                        #thread count (default=4)
                        
  -v, --verbose         #verbosity level (-vvvv is level 4)
```

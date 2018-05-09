# go-aes

## Usage to go-aes:

```aes -a (e|d) [options] [file]```

Note:
- If no file is given stadard input will be used to read data from.
- If no output file is given stadard output will be used to write data to.
- the action option is mandentory
- in case of 'decryption' the key flag (k) is mandentory

## Usage Examples:

 encyrpt file 'myfile', with a new random key and write to file 'out.aes'
    ```aes -a e -o out.aes myfile```

Note: if you omit the '-k' key flag a new random key will be generated your you.
      The generated key will be printed out on standard error

encyrpt file 'myfile', with a new random key and write to file 'out.aes'
   ```cat myfile | aes -a e -o out.aes```

decrypt file 'out.aes', with given key and write cleartext to 'myfile.copy'
   ```aes -a d -o myfile.copy -k isTll4ijS5lSOWouDHgBo2j9VOXub1iXoUBbiNcmWzQ= out.aes```

## Options:

  -a string
    	action: (e)ncrypt, (d)ecrypt
  -k string
    	key to be used as base64 url encoded string
  -o string
    	file to write output to


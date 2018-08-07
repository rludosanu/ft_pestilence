# ELF binary infection for x86_64 executable files

## Synopsis
Pestilence is a self-replicating oligomorphic virus.
It recusively replicates in /tmp/test(2) directories adding a custom "signature" string into each infected file.
To check the signature, simply copy/paste the following command :
`strings /tmp/test* | grep <signatureName>`

## Mandatory
- [x] Infect all of the binaries located in /tmp/test and /tmp/test2 directories
- [x] Infect all of the binaries of type executable ELF x86_64
- [x] Insert a signature like 'Pestilence version 1.0 (c)oded by first-login - second-login'
- [x] Create an obfuscation method to hide the infection routine
- [x] Create a deobfuscation method that will run the infection
- [x] DO NOT re-infect the an already infected file
- [x] DO NOT run infection if a specific process is running on host
- [x] DO NOT run infection if the program is launched into gdb, etc

## Bonus
- [x] Infect all files from the root directory
- [ ] Pack the binary with a compression algorithm
- [ ] Add a secret backdoor (open port, ...)

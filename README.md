This repo contains useful code to perform various security tools, such as
* Generate a private key
* Generate a self signed certificate
* Digitally sign a file
* Verify a digital signature

# OpenSSL commands

Create a private key
> openssl genrsa -out key.pem 1024

Create a self signed certificate
> openssl req -new -x509 -out cert.pem -key key.pem -days 3650 -extensions v3_req -config configurationFile.cfg

Digitally sign a file, data.txt with the private key, key.pem and output the digital signature to signature.dat
> openssl dgst -sha256 -sign key.pem -out signature.dat data.txt

Verify the data in data.txt has been signed by the identify in cert.pem by verifying the signature in signature.dat
> openssl dgst -sha256 -verify  <(openssl x509 -in cert.pem  -pubkey -noout) -signature signature.dat data.txt

Generate a private key and self signed certificate using the script without the need for a config file. Each of the 
used in this command can be overridden with values that you may need in the self signed cert 
> ./scripts/generateCertAndKey.sh -n test -c IE -u orgunit -o organization -e myemail@domain.com -s state -l location

# Java Code
## Generate a private key
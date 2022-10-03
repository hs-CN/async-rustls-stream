openssl genrsa -out ca.key 2048
open genrsa -text -noout ca.key
openssl req -new -out ca.csr -key ca.key -config req.cnf
openssl req -text -noout -in ca.csr
openssl x509 -req -days 3650 -in ca.csr -signkey ca.key -out ca.crt -extensions req_ext -extfile req.cnf
openssl x509 -text -noout -in ca.crt
if [[ "$1" = "rsa" ]]; then
    echo "Compiling for RSA ..."
    make all > /dev/null
elif [[ "$1" = "ecc" ]]; then
    echo "Compiling for ECC ..."
    make all ARGS="-DELLIPTIC" > /dev/null
else
    echo "Invalid argument. Has to be 'rsa' or 'ecc'."
    exit 1
fi

# Make sure the key does not exists
./bin/delete_key.exe > /dev/null 2>&1

echo "Creating key ..."
./bin/create_key.exe > /dev/null
./bin/export_key.exe > public.pem

echo "Signing ..."
SIGNATURE=$(./bin/sign.exe)

./bin/delete_key.exe > /dev/null

# ECC signature needs to be converted to ASN.1 format
if [[ "$1" = "ecc" ]]; then
    R=${SIGNATURE:0:96}
    S=${SIGNATURE:96:96}

    cat<<EOF > tmp.txt
asn1=SEQUENCE:seq
[seq]
r=INTEGER:0x$R
s=INTEGER:0x$S
EOF

    openssl asn1parse -genconf tmp.txt -out sig.sha256 -noout
    rm tmp.txt
else
    echo -n $SIGNATURE | xxd -r -p > sig.sha256
fi

# Signature verification
echo -n "Secret challenge" \
    | openssl dgst -sha256 -signature sig.sha256 -verify public.pem

rm sig.sha256
rm public.pem

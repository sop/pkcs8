# PKCS #8 Encrypted Private Keys for Unit Testing

Generate private key:

    openssl genrsa -out private_key.pem

Generate v1 encrypted private keys:

    for alg in PBE-MD2-DES PBE-MD5-DES PBE-SHA1-RC2-64 PBE-MD2-RC2-64 \
      PBE-MD5-RC2-64 PBE-SHA1-DES PBE-SHA1-RC4-128 PBE-SHA1-RC4-40 \
      PBE-SHA1-3DES PBE-SHA1-2DES PBE-SHA1-RC2-128 PBE-SHA1-RC2-40; do
        openssl pkcs8 -in private_key.pem -topk8 -v1 "$alg" \
          -passout pass:password -out "key_$alg.pem" || echo "$alg failed"
        [[ -s "key_$alg.pem" ]] || rm "key_$alg.pem"
    done

Generate v2 encrypted private keys:

    openssl pkcs8 -in private_key.pem -topk8 -v2 des3 \
      -passout pass:password -out key_v2_des3.pem &&
    openssl pkcs8 -in private_key.pem -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA512 \
      -passout pass:password -out key_v2_aes.pem

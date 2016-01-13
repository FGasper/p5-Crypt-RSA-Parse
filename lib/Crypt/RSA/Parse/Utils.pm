package Crypt::RSA::Parse::Utils;

#cf. RFC 3447 appendix A.1.1
#
#replacing INTEGER with BIG_FAT_INTEGER to facilitate “lite” mode
#which doesn’t bring in Math::BigInt.
my $ASN1_TEMPLATE = q<

    BIG_FAT_INTEGER ::= <WHAT_IS_BIG_FAT_INTEGER>

    RSAPublicKey ::= SEQUENCE {
        modulus           BIG_FAT_INTEGER,  -- n
        publicExponent    INTEGER   -- e
    }

    -- FG: simplified from RFC for Convert::ASN1
    Version ::= INTEGER

    OtherPrimeInfo ::= SEQUENCE {
        prime             BIG_FAT_INTEGER,  -- ri
        exponent          BIG_FAT_INTEGER,  -- di
        coefficient       BIG_FAT_INTEGER   -- ti
    }

    -- FG: simplified from RFC for Convert::ASN1
    OtherPrimeInfos ::= SEQUENCE OF OtherPrimeInfo

    RSAPrivateKey ::= SEQUENCE {
        version           Version,
        modulus           BIG_FAT_INTEGER,  -- n
        publicExponent    INTEGER,  -- e
        privateExponent   BIG_FAT_INTEGER,  -- d
        prime1            BIG_FAT_INTEGER,  -- p
        prime2            BIG_FAT_INTEGER,  -- q
        exponent1         BIG_FAT_INTEGER,  -- d mod (p-1)
        exponent2         BIG_FAT_INTEGER,  -- d mod (q-1)
        coefficient       BIG_FAT_INTEGER,  -- (inverse of q) mod p
        otherPrimeInfos   OtherPrimeInfos OPTIONAL
    }

    -- cf. RFC 3280 4.1.1.2
    AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm               OBJECT IDENTIFIER,
        parameters              ANY DEFINED BY algorithm OPTIONAL
    }

    -- cf. RFC 5208 appendix A
    PrivateKeyInfo ::= SEQUENCE {
        version Version,
        privateKeyAlgorithm AlgorithmIdentifier,
        privateKey PrivateKey
    }

    PrivateKey ::= OCTET STRING

    -- cf. RFC 3280 4.1
    SubjectPublicKeyInfo  ::=  SEQUENCE  {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING
    }
>;

sub get_template {
    my ($what_is_big_fat_int) = @_;

    my $template = $ASN1_TEMPLATE;
    $template =~ s/<WHAT_IS_BIG_FAT_INTEGER>/$what_is_big_fat_int/;

    return $template;
}

1;

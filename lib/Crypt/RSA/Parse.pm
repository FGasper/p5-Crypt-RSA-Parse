package Crypt::RSA::Parse;

use strict;
use warnings;

our $VERSION = 0.01;

=pod

=encoding utf-8

=head1 NAME

Crypt::RSA::Parse - Parse RSA keys

=head1 SYNOPSIS

    #General-purpose, native RSA or PKCS8, DER or PEM
    my $public_rsa = Crypt::RSA::Parse::public($key_str);
    my $private_rsa = Crypt::RSA::Parse::private($private_key_str);

    $public_rsa->exponent();
    $public_rsa->modulus();     #isa Math::BigInt
    $public_rsa->size();        #i.e., the modulus length in bits

    $private_rsa->version();        #usually 0
    $private_rsa->modulus();        #isa Math::BigInt
    $private_rsa->size();           #i.e., the modulus length in bits

    $private_rsa->publicExponent();     #same as “exponent” on public keys
    $private_rsa->privateExponent();    #isa Math::BigInt
    $private_rsa->prime1();             #isa Math::BigInt
    $private_rsa->prime2();             #isa Math::BigInt
    $private_rsa->exponent1();          #isa Math::BigInt
    $private_rsa->exponent2();          #isa Math::BigInt
    $private_rsa->coefficient();        #isa Math::BigInt

    #Only checks PKCS8, DER or PEM
    $public_rsa = Crypt::RSA::Parse::public_pkcs8($pkcs8_str);
    $private_rsa = Crypt::RSA::Parse::private_pkcs8($pkcs8_str);

    {
        #If, for whatever reason, you don’t like MIME::Base64,
        #then customize this. The module must have a decode() function.
        #
        local $Crypt::RSA::Parse::BASE64_MODULE = '..';

        Crypt::RSA::Parse::...
    }

=head1 DESCRIPTION

Not much else to say: it parses RSA keys for useful information!

The public keys are represented via the C<Crypt::RSA::Parse::Public>
class, while private keys are represented via C<Crypt::RSA::Parse::Private>.

=cut

use Crypt::RSA::Parse::Utils ();

our $BASE64_MODULE = 'MIME::Base64';

my $asn1;

sub _decode_macro {
    my ( $der_r, $macro ) = ( \$_[0], $_[1] );

    my $parser = $asn1->find_or_die($macro);

    return $parser->decode($$der_r);
}

sub _init {
    my ($pem_or_der_r) = \$_[0];

    if ( !$asn1 ) {
        $asn1 = Crypt::RSA::Parse::Convert_ASN1->new();
        $asn1->prepare_or_die( Crypt::RSA::Parse::Utils::get_template('INTEGER') );
    }

    if ( $$pem_or_der_r =~ m<\A-> ) {
        _pem_to_der($$pem_or_der_r);
    }

    return;
}

#Checks for RSA format first, then falls back to PKCS8.
sub private {
    my ($pem_or_der) = @_;

    _init($pem_or_der);

    my $parsed = _decode_rsa($pem_or_der) || do {
        my $pkcs8 = _decode_pkcs8($pem_or_der) or do {
            die sprintf( "Failed to parse as either RSA or PKCS8: %s", $asn1->error() );
        };

        _decode_rsa_within_pkcs8_or_die($pkcs8);
    };

    return _new_private($parsed);
}

#Like private(), but only does PKCS8.
sub private_pkcs8 {
    my ($pem_or_der) = @_;

    _init($pem_or_der);

    my $pkcs8 = _decode_pkcs8($pem_or_der) or do {
        die sprintf("Failed to parse PKCS8!");
    };

    my $parsed = _decode_rsa_within_pkcs8_or_die($pkcs8);

    return _new_private($parsed);
}

#Checks for RSA format first, then falls back to PKCS8.
sub public {
    my ($pem_or_der) = @_;

    _init($pem_or_der);

    my $parsed = _decode_rsa_public($pem_or_der) || do {
        my $pkcs8 = _decode_pkcs8_public($pem_or_der) or do {
            die sprintf( "Failed to parse as either RSA or PKCS8: %s", $asn1->error() );
        };

        _decode_rsa_public_within_pkcs8_or_die($pkcs8);
    };

    return _new_public($parsed);
}

#Like public(), but only does PKCS8.
sub public_pkcs8 {
    my ($pem_or_der) = @_;

    _init($pem_or_der);

    my $pkcs8 = _decode_pkcs8_public($pem_or_der) or do {
        die sprintf( "Failed to parse PKCS8: %s", $asn1->error() );
    };

    my $parsed = _decode_rsa_public_within_pkcs8_or_die($pkcs8);

    return _new_public($parsed);
}

sub _decode_rsa {
    my ($der_r) = \$_[0];

    return _decode_macro( $$der_r, 'RSAPrivateKey' );
}

sub _decode_rsa_public {
    my ($der_r) = \$_[0];

    return _decode_macro( $$der_r, 'RSAPublicKey' );
}

sub _decode_rsa_within_pkcs8_or_die {
    my ($pkcs8) = @_;

    return _decode_rsa( $pkcs8->{'privateKey'} ) || do {
        die sprintf("Failed to parse RSA within PKCS8!");
    };
}

sub _decode_rsa_public_within_pkcs8_or_die {
    my ($pkcs8) = @_;

    return _decode_rsa_public( $pkcs8->{'subjectPublicKey'}[0] ) || do {
        die sprintf("Failed to parse RSA within PKCS8!");
    };
}

sub _decode_pkcs8 {
    my ($der_r) = \$_[0];

    return _decode_macro( $$der_r, 'PrivateKeyInfo' );
}

sub _decode_pkcs8_public {
    my ($der_r) = \$_[0];

    return _decode_macro( $$der_r, 'SubjectPublicKeyInfo' );
}

sub _new_public {
    my ($parsed) = @_;

    return Crypt::RSA::Parse::Public->new(
        modulus  => $parsed->{'modulus'},
        exponent => $parsed->{'publicExponent'},
    );
}

sub _new_private {
    my ($parsed) = @_;

    return Crypt::RSA::Parse::Private->new(%$parsed);
}

#Modifies in-place.
sub _pem_to_der {
    my $str_r = \$_[0];

    local $@;
    eval "require $BASE64_MODULE" or die;

    $$str_r =~ s<^-.+?$><>msg;

    $$str_r = $BASE64_MODULE->can('decode')->($$str_r);

    return;
}

#----------------------------------------------------------------------
package Crypt::RSA::Parse::Base;

use Mo qw(required);

has modulus => ( required => 1 );

sub size {
    my ($self) = @_;

    return length( $self->modulus()->as_bin() ) - 2;
}

#----------------------------------------------------------------------
package Crypt::RSA::Parse::Public;

use Mo qw(required);

extends 'Crypt::RSA::Parse::Base';

has exponent => ( required => 1 );

#----------------------------------------------------------------------
package Crypt::RSA::Parse::Private;

use Mo qw(required);

extends 'Crypt::RSA::Parse::Base';

has version => ( required => 1 );

has publicExponent  => ( required => 1 );
has privateExponent => ( required => 1 );

has prime1 => ( required => 1 );
has prime2 => ( required => 1 );

has exponent1 => ( required => 1 );
has exponent2 => ( required => 1 );

has coefficient => ( required => 1 );

#----------------------------------------------------------------------
package Crypt::RSA::Parse::Convert_ASN1;

use parent 'Convert::ASN1';

sub prepare_or_die {
    my ( $self, $asn1_r ) = ( $_[0], \$_[1] );

    my $ret = $self->prepare($$asn1_r);

    if ( !defined $ret ) {
        die sprintf( "Failed to prepare ASN.1 description: %s", $self->error() );
    }

    return $ret;
}

sub find_or_die {
    my ( $self, $macro ) = @_;

    return $self->find($macro) || do {
        die sprintf( "Failed to find ASN.1 macro “$macro”: %s", $self->error() );
    };
}

#----------------------------------------------------------------------

=head1 AUTHOR

    Felipe M. L. Gasper
    CPAN ID: FELIPE

=head1 REPOSITORY

    https://github.com/FGasper/p5-Crypt-RSA-Parse

=head1 COPYRIGHT

This program is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

The full text of the license can be found in the
LICENSE file included with this module.

=cut

1;

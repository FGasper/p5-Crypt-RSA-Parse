

use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME         => 'Crypt::RSA::Parse',
    VERSION_FROM => 'lib/Crypt/RSA/Parse.pm', # finds \$VERSION
    AUTHOR       => 'Felipe M. L. Gasper',
    ABSTRACT     => 'Parse RSA keys',
    PREREQ_PM    => {
                     'Convert::ASN1' => 0.27,
                     'MIME::Base64' => 3.15,
                     'Mo' => 0.39,
                     'Test::Simple' => 0.44,
                    },
);

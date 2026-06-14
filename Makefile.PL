use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'Perl::Log::Analyzer',
    AUTHOR           => 'Perl Log Analyzer Team',
    VERSION_FROM     => 'lib/Perl/Log/Analyzer.pm',
    ABSTRACT_FROM    => 'lib/Perl/Log/Analyzer.pm',
    LICENSE          => 'mit',
    MIN_PERL_VERSION => '5.010',
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => '0',
    },
    BUILD_REQUIRES => {},
    TEST_REQUIRES => {
        'Test::More' => '0.96',
    },
    PREREQ_PM => {
        'Getopt::Long' => '0',
        'Text::CSV'    => '0',
        'JSON::PP'     => '0',
        'List::Util'   => '0',
    },
    EXE_FILES => [
        'bin/log_analyzer',
        'bin/generate_logs',
    ],
    META_MERGE => {
        'meta-spec' => { version => 2 },
        resources   => {
            repository => {
                type => 'git',
                url  => 'https://github.com/qqwozz/Perl_anlz.git',
                web  => 'https://github.com/qqwozz/Perl_anlz',
            },
        },
    },
);

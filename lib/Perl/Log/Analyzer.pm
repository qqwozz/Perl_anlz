package Perl::Log::Analyzer;

use strict;
use warnings;
use 5.010;

our $VERSION = '1.00';

use Perl::Log::Analyzer::Parser;
use Perl::Log::Analyzer::Reporter;

sub new {
    my ($class, %args) = @_;
    
    my $self = {
        file            => $args{file}            || die "file parameter required\n",
        top_n           => $args{top_n}           || 10,
        suspicious_threshold => $args{suspicious_threshold} || 100,
        error_threshold => $args{error_threshold} || 50,
        verbose         => $args{verbose}         || 0,
    };
    
    bless $self, $class;
    $self->_validate();
    return $self;
}

sub _validate {
    my $self = shift;
    
    die "File '$self->{file}' does not exist\n" unless -e $self->{file};
    die "File '$self->{file}' is not readable\n" unless -r $self->{file};
}

sub analyze {
    my $self = shift;
    
    my $parser = Perl::Log::Analyzer::Parser->new(
        top_n                => $self->{top_n},
        suspicious_threshold => $self->{suspicious_threshold},
    );
    
    my $stats = $parser->parse($self->{file});
    
    return $stats;
}

sub report {
    my ($self, $stats) = @_;
    
    my $reporter = Perl::Log::Analyzer::Reporter->new(
        top_n       => $self->{top_n},
        error_threshold => $self->{error_threshold},
    );
    
    return $reporter->generate($stats);
}

1;

__END__

=head1 NAME

Perl::Log::Analyzer - Apache/nginx access log analyzer

=head1 VERSION

Version 1.00

=head1 SYNOPSIS

    use Perl::Log::Analyzer;
    
    my $analyzer = Perl::Log::Analyzer->new(
        file    => 'access.log',
        top_n   => 20,
    );
    
    my $stats = $analyzer->analyze();
    my $report = $analyzer->report($stats);
    print $report;

=head1 DESCRIPTION

Perl::Log::Analyzer is a powerful tool for analyzing Apache/nginx access logs.
It provides comprehensive statistics including:

=over 4

=item * Top IP addresses by request count

=item * HTTP method distribution

=item * Response code analysis

=item * Security threat detection

=item * Error rate analysis

=item * User agent statistics

=back

=head1 METHODS

=head2 new(%args)

Creates a new analyzer instance.

Required parameters:

=over 4

=item * file - Path to the log file

=back

Optional parameters:

=over 4

=item * top_n - Number of top items to display (default: 10)

=item * suspicious_threshold - Threshold for suspicious IP detection (default: 100)

=item * error_threshold - Threshold for high error rate detection (default: 50)

=item * verbose - Enable verbose output (default: 0)

=back

=head2 analyze()

Analyzes the log file and returns a hash reference with statistics.

=head2 report($stats)

Generates a formatted report from the statistics hash.

=head1 AUTHOR

Perl Log Analyzer Team

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

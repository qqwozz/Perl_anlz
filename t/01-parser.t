#!/usr/bin/env perl

use strict;
use warnings;
use Test::More tests => 8;
use File::Temp qw(tempfile);
use FindBin;

use lib "$FindBin::Bin/../lib";
use Perl::Log::Analyzer::Parser;
use Perl::Log::Analyzer::Reporter;

my ($fh, $temp_file) = tempfile(UNLINK => 1, SUFFIX => '.log');

my @test_lines = (
    '192.168.1.1 - - [10/Jan/2024:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
    '192.168.1.2 - - [10/Jan/2024:12:01:00 +0000] "POST /api/users HTTP/1.1" 201 567 "-" "curl/7.68.0"',
    '192.168.1.1 - - [10/Jan/2024:12:02:00 +0000] "GET /about HTTP/1.1" 200 890 "-" "Mozilla/5.0"',
    '10.0.0.1 - - [10/Jan/2024:12:03:00 +0000] "GET /admin HTTP/1.1" 403 0 "-" "Mozilla/5.0"',
    '10.0.0.1 - - [10/Jan/2024:12:04:00 +0000] "GET /wp-admin HTTP/1.1" 404 0 "-" "nikto/2.1.6"',
    '172.16.0.1 - - [10/Jan/2024:12:05:00 +0000] "GET /etc/passwd HTTP/1.1" 403 0 "-" "curl/7.68.0"',
    '8.8.8.8 - - [10/Jan/2024:12:06:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Googlebot/2.1"',
    '1.1.1.1 - - [10/Jan/2024:12:07:00 +0000] "GET /products HTTP/1.1" 500 0 "-" "Mozilla/5.0"',
);

foreach my $line (@test_lines) {
    print $fh "$line\n";
}
close($fh);

my $parser = Perl::Log::Analyzer::Parser->new(top_n => 5);
my $stats = $parser->parse($temp_file);

is($stats->{total_requests}, 8, 'Correct total request count');
is(scalar keys %{$stats->{ip_count}}, 6, 'Correct unique IP count');
is($stats->{method_count}{GET}, 7, 'Correct GET count');
is($stats->{method_count}{POST}, 1, 'Correct POST count');
is($stats->{status_count}{200}, 3, 'Correct 200 status count');
is($stats->{status_count}{404}, 1, 'Correct 404 status count');
is(scalar keys %{$stats->{suspicious_ips}}, 3, 'Detected suspicious IPs');
ok(exists $stats->{scan_attempts}, 'Security scan attempts tracked');

done_testing();

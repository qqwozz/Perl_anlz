#!/usr/bin/env perl

use strict;
use warnings;
use Test::More tests => 5;
use File::Temp qw(tempfile);
use FindBin;

use lib "$FindBin::Bin/../lib";
use Perl::Log::Analyzer;

my ($fh, $temp_file) = tempfile(UNLINK => 1, SUFFIX => '.log');

my @test_lines = (
    '192.168.1.1 - - [10/Jan/2024:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
    '192.168.1.2 - - [10/Jan/2024:12:01:00 +0000] "POST /api/users HTTP/1.1" 201 567 "-" "curl/7.68.0"',
);

foreach my $line (@test_lines) {
    print $fh "$line\n";
}
close($fh);

my $analyzer = Perl::Log::Analyzer->new(
    file  => $temp_file,
    top_n => 5,
);

isa_ok($analyzer, 'Perl::Log::Analyzer', 'Analyzer object created');

my $stats = $analyzer->analyze();
is($stats->{total_requests}, 2, 'Analyze returns correct stats');

my $report = $analyzer->report($stats);
like($report, qr/LOG ANALYSIS REPORT/, 'Report generated successfully');
like($report, qr/Total requests:\s+2/, 'Report contains correct data');
like($report, qr/Analysis complete/, 'Report contains footer');

done_testing();

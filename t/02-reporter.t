#!/usr/bin/env perl

use strict;
use warnings;
use Test::More tests => 5;
use FindBin;

use lib "$FindBin::Bin/../lib";
use Perl::Log::Analyzer::Reporter;

my $stats = {
    total_requests => 1000,
    total_bytes    => 5000000,
    total_errors   => 50,
    ip_count       => { '192.168.1.1' => 200, '10.0.0.1' => 150, '8.8.8.8' => 100 },
    method_count   => { GET => 800, POST => 150, PUT => 30, DELETE => 20 },
    url_count      => { '/index.html' => 300, '/api/users' => 200, '/about' => 150 },
    status_count   => { 200 => 900, 301 => 20, 404 => 60, 500 => 20 },
    ua_count       => { 'Mozilla/5.0' => 800, 'curl/7.68.0' => 200 },
    error_urls     => { '/admin' => 30, '/api/users' => 20 },
    error_ips      => { '10.0.0.1' => 25, '192.168.1.1' => 15 },
    suspicious_ips => { '10.0.0.1' => 10 },
    scan_attempts  => { '/wp-admin' => 5, '/etc/passwd' => 3 },
    high_error_ips_final => { '10.0.0.1' => 60 },
    top_n          => 10,
};

my $reporter = Perl::Log::Analyzer::Reporter->new(top_n => 10);
my $report = $reporter->generate($stats);

like($report, qr/LOG ANALYSIS REPORT/, 'Report contains header');
like($report, qr/Total requests:\s+1000/, 'Report contains total requests');
like($report, qr/SECURITY ANALYSIS/, 'Report contains security section');
like($report, qr/192\.168\.1\.1/, 'Report contains IP addresses');
like($report, qr/Analysis complete/, 'Report contains footer');

done_testing();

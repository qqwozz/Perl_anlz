package Perl::Log::Analyzer::Parser;

use strict;
use warnings;
use 5.010;

sub new {
    my ($class, %args) = @_;
    
    my $self = {
        top_n                => $args{top_n}                || 10,
        suspicious_threshold => $args{suspicious_threshold} || 100,
        ip_count             => {},
        method_count         => {},
        url_count            => {},
        status_count         => {},
        ua_count             => {},
        error_urls           => {},
        error_ips            => {},
        suspicious_ips       => {},
        scan_attempts        => {},
        high_error_rate_ips  => {},
        total_requests       => 0,
        total_bytes          => 0,
        total_errors         => 0,
    };
    
    bless $self, $class;
    return $self;
}

my @SUSPICIOUS_PATTERNS = (
    qr/\.\.\/|\.\.\\/,                    # Path traversal
    qr/etc\/passwd/,                       # passwd access attempt
    qr/union\s+select/i,                   # SQL injection
    qr/wp-admin|wp-login/,                 # WordPress attacks
    qr/phpmyadmin|mysql|phpinfo/,          # Database admin access
    qr/\.env|\.git|\.svn/,                 # System file access
    qr/<script|javascript:|onerror=/i,     # XSS attempts
    qr/bin\/bash|cmd\.exe|powershell/i,    # Command execution
    qr/\.\.\%5c|\.\.\%2f/i,               # URL encoded path traversal
    qr/\%00|null/i,                        # Null byte injection
    qr/exec|eval|system|passthru/i,        # PHP code execution
);

my @SUSPICIOUS_UA_PATTERNS = (
    qr/nmap|nikto|sqlmap|nessus|acunetix/i,
    qr/curl|wget|python-requests|perl|ruby/i,
    qr/winhttp|httpclient/i,
    qr/\(\);|masscan|zgrab/i,
);

my $LOG_PATTERN = qr/^(\S+) \S+ \S+ \[(.*?)\] "(\S+) (\S+) \S+" (\d{3}) (\d+) "([^"]*)" "([^"]*)"$/;

sub parse {
    my ($self, $file) = @_;
    
    open(my $fh, '<', $file) or die "Cannot open '$file': $!\n";
    
    while (my $line = <$fh>) {
        chomp $line;
        $self->{total_requests}++;
        
        if ($line =~ $LOG_PATTERN) {
            $self->_process_line($1, $2, $3, $4, $5, $6, $7, $8);
        } else {
            warn "Failed to parse line: $line\n" if $self->{verbose};
        }
    }
    
    close($fh);
    $self->_calculate_error_rates();
    
    return $self->_get_stats();
}

sub _process_line {
    my ($self, $ip, $date, $method, $url, $status, $bytes, $referer, $ua) = @_;
    
    $self->{ip_count}{$ip}++;
    $self->{method_count}{$method}++;
    $self->{url_count}{$url}++;
    $self->{status_count}{$status}++;
    $self->{ua_count}{$ua}++ if $ua;
    $self->{total_bytes} += $bytes if $bytes;
    
    if ($status >= 400) {
        $self->{total_errors}++;
        $self->{error_urls}{$url}++;
        $self->{error_ips}{$ip}++;
        $self->{high_error_rate_ips}{$ip}++;
    }
    
    $self->_check_suspicious($ip, $url, $ua);
}

sub _check_suspicious {
    my ($self, $ip, $url, $ua) = @_;
    
    foreach my $pattern (@SUSPICIOUS_PATTERNS) {
        if ($url =~ $pattern) {
            $self->{suspicious_ips}{$ip}++;
            $self->{scan_attempts}{$url}++;
            last;
        }
    }
    
    foreach my $pattern (@SUSPICIOUS_UA_PATTERNS) {
        if ($ua =~ $pattern) {
            $self->{suspicious_ips}{$ip}++;
            $self->{scan_attempts}{$url}++;
            last;
        }
    }
}

sub _calculate_error_rates {
    my $self = shift;
    
    my %high_error_ips_final;
    foreach my $ip (keys %{$self->{high_error_rate_ips}}) {
        my $error_count = $self->{high_error_rate_ips}{$ip};
        my $total_ip_requests = $self->{ip_count}{$ip} || 1;
        my $error_percentage = ($error_count / $total_ip_requests) * 100;
        
        if ($error_percentage > 50 && $error_count > 10) {
            $high_error_ips_final{$ip} = $error_percentage;
        }
    }
    
    $self->{high_error_ips_final} = \%high_error_ips_final;
}

sub _get_stats {
    my $self = shift;
    
    return {
        total_requests       => $self->{total_requests},
        total_bytes          => $self->{total_bytes},
        total_errors         => $self->{total_errors},
        ip_count             => $self->{ip_count},
        method_count         => $self->{method_count},
        url_count            => $self->{url_count},
        status_count         => $self->{status_count},
        ua_count             => $self->{ua_count},
        error_urls           => $self->{error_urls},
        error_ips            => $self->{error_ips},
        suspicious_ips       => $self->{suspicious_ips},
        scan_attempts        => $self->{scan_attempts},
        high_error_ips_final => $self->{high_error_ips_final},
        top_n                => $self->{top_n},
    };
}

1;

__END__

=head1 NAME

Perl::Log::Analyzer::Parser - Log file parser

=head1 SYNOPSIS

    my $parser = Perl::Log::Analyzer::Parser->new(top_n => 10);
    my $stats = $parser->parse('access.log');

=head1 DESCRIPTION

Parses Apache/nginx access log files and extracts statistics.

=head1 METHODS

=head2 new(%args)

Creates a new parser instance.

=head2 parse($file)

Parses the log file and returns statistics.

=cut

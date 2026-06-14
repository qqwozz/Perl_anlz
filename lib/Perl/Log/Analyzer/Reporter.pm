package Perl::Log::Analyzer::Reporter;

use strict;
use warnings;
use 5.010;

sub new {
    my ($class, %args) = @_;
    
    my $self = {
        top_n           => $args{top_n}           || 10,
        error_threshold => $args{error_threshold} || 50,
    };
    
    bless $self, $class;
    return $self;
}

sub generate {
    my ($self, $stats) = @_;
    
    my $report = '';
    
    $report .= $self->_header($stats);
    $report .= $self->_general_stats($stats);
    $report .= $self->_top_ips($stats);
    $report .= $self->_method_stats($stats);
    $report .= $self->_top_urls($stats);
    $report .= $self->_status_stats($stats);
    $report .= $self->_error_analysis($stats);
    $report .= $self->_security_analysis($stats);
    $report .= $self->_user_agents($stats);
    $report .= $self->_footer();
    
    return $report;
}

sub _header {
    my ($self, $stats) = @_;
    
    my $header = '';
    $header .= "=" x 60 . "\n";
    $header .= "LOG ANALYSIS REPORT\n";
    $header .= "=" x 60 . "\n\n";
    
    return $header;
}

sub _general_stats {
    my ($self, $stats) = @_;
    
    my $section = '';
    $section .= "GENERAL STATISTICS\n";
    $section .= "-" x 40 . "\n";
    $section .= sprintf "Total requests:    %d\n", $stats->{total_requests};
    $section .= sprintf "Unique IPs:        %d\n", scalar keys %{$stats->{ip_count}};
    $section .= sprintf "Total data:        %s\n", $self->_format_bytes($stats->{total_bytes});
    $section .= "\n";
    
    return $section;
}

sub _top_ips {
    my ($self, $stats) = @_;
    
    my $section = '';
    $section .= sprintf "TOP %d IPs BY REQUEST COUNT\n", $self->{top_n};
    $section .= "-" x 40 . "\n";
    
    my $count = 0;
    foreach my $ip (sort { $stats->{ip_count}{$b} <=> $stats->{ip_count}{$a} } 
                    keys %{$stats->{ip_count}}) {
        my $percentage = ($stats->{ip_count}{$ip} / $stats->{total_requests}) * 100;
        $section .= sprintf "%-15s : %d requests (%.1f%%)\n", 
            $ip, $stats->{ip_count}{$ip}, $percentage;
        last if ++$count >= $self->{top_n};
    }
    $section .= "\n";
    
    return $section;
}

sub _method_stats {
    my ($self, $stats) = @_;
    
    my $section = '';
    $section .= "HTTP METHOD DISTRIBUTION\n";
    $section .= "-" x 40 . "\n";
    
    foreach my $method (sort keys %{$stats->{method_count}}) {
        my $percentage = ($stats->{method_count}{$method} / $stats->{total_requests}) * 100;
        $section .= sprintf "%-10s : %d requests (%.1f%%)\n", 
            $method, $stats->{method_count}{$method}, $percentage;
    }
    $section .= "\n";
    
    return $section;
}

sub _top_urls {
    my ($self, $stats) = @_;
    
    my $section = '';
    $section .= sprintf "TOP %d URLs BY REQUEST COUNT\n", $self->{top_n};
    $section .= "-" x 40 . "\n";
    
    my $count = 0;
    foreach my $url (sort { $stats->{url_count}{$b} <=> $stats->{url_count}{$a} } 
                     keys %{$stats->{url_count}}) {
        my $percentage = ($stats->{url_count}{$url} / $stats->{total_requests}) * 100;
        $section .= sprintf "%-30s : %d requests (%.1f%%)\n", 
            substr($url, 0, 30), $stats->{url_count}{$url}, $percentage;
        last if ++$count >= $self->{top_n};
    }
    $section .= "\n";
    
    return $section;
}

sub _status_stats {
    my ($self, $stats) = @_;
    
    my $section = '';
    $section .= "RESPONSE CODE DISTRIBUTION\n";
    $section .= "-" x 40 . "\n";
    
    foreach my $status (sort keys %{$stats->{status_count}}) {
        my $percentage = ($stats->{status_count}{$status} / $stats->{total_requests}) * 100;
        $section .= sprintf "%-3s : %d requests (%.1f%%)\n", 
            $status, $stats->{status_count}{$status}, $percentage;
    }
    $section .= "\n";
    
    return $section;
}

sub _error_analysis {
    my ($self, $stats) = @_;
    
    my $section = '';
    $section .= "ERROR ANALYSIS\n";
    $section .= "-" x 40 . "\n";
    
    my $error_percentage = $stats->{total_requests} ? 
        ($stats->{total_errors} / $stats->{total_requests}) * 100 : 0;
    
    $section .= sprintf "Total errors (4xx, 5xx): %d\n", $stats->{total_errors};
    $section .= sprintf "Error rate: %.2f%%\n\n", $error_percentage;
    
    $section .= sprintf "TOP %d URLs WITH ERRORS\n", $self->{top_n};
    my $count = 0;
    foreach my $url (sort { $stats->{error_urls}{$b} <=> $stats->{error_urls}{$a} } 
                     keys %{$stats->{error_urls}}) {
        my $error_count = $stats->{error_urls}{$url};
        my $total_url_requests = $stats->{url_count}{$url} || 1;
        my $error_rate = ($error_count / $total_url_requests) * 100;
        $section .= sprintf "%-30s : %d errors (%.1f%%)\n", 
            substr($url, 0, 30), $error_count, $error_rate;
        last if ++$count >= $self->{top_n};
    }
    $section .= "\n";
    
    $section .= sprintf "TOP %d IPs WITH ERRORS\n", $self->{top_n};
    $count = 0;
    foreach my $ip (sort { $stats->{error_ips}{$b} <=> $stats->{error_ips}{$a} } 
                    keys %{$stats->{error_ips}}) {
        my $error_count = $stats->{error_ips}{$ip};
        my $total_ip_requests = $stats->{ip_count}{$ip} || 1;
        my $error_rate = ($error_count / $total_ip_requests) * 100;
        $section .= sprintf "%-15s : %d errors (%.1f%%)\n", 
            $ip, $error_count, $error_rate;
        last if ++$count >= $self->{top_n};
    }
    $section .= "\n";
    
    if (keys %{$stats->{high_error_ips_final}}) {
        $section .= "IPs WITH HIGH ERROR RATE (>50% and >10 errors)\n";
        foreach my $ip (sort { $stats->{high_error_ips_final}{$b} <=> $stats->{high_error_ips_final}{$a} } 
                        keys %{$stats->{high_error_ips_final}}) {
            my $error_rate = $stats->{high_error_ips_final}{$ip};
            my $error_count = $stats->{error_ips}{$ip};
            my $total_requests_ip = $stats->{ip_count}{$ip};
            $section .= sprintf "%-15s : %.1f%% errors (%d of %d requests)\n", 
                $ip, $error_rate, $error_count, $total_requests_ip;
        }
        $section .= "\n";
    }
    
    return $section;
}

sub _security_analysis {
    my ($self, $stats) = @_;
    
    my $section = '';
    $section .= "SECURITY ANALYSIS\n";
    $section .= "-" x 40 . "\n";
    
    if (keys %{$stats->{suspicious_ips}}) {
        $section .= sprintf "TOP %d SUSPICIOUS IPs\n", $self->{top_n};
        my $count = 0;
        foreach my $ip (sort { $stats->{suspicious_ips}{$b} <=> $stats->{suspicious_ips}{$a} } 
                        keys %{$stats->{suspicious_ips}}) {
            my $suspicious_count = $stats->{suspicious_ips}{$ip};
            my $total_ip_requests = $stats->{ip_count}{$ip} || 1;
            my $suspicious_percentage = ($suspicious_count / $total_ip_requests) * 100;
            $section .= sprintf "%-15s : %d suspicious requests (%.1f%%)\n", 
                $ip, $suspicious_count, $suspicious_percentage;
            last if ++$count >= $self->{top_n};
        }
        $section .= "\n";
        
        $section .= sprintf "TOP %d SUSPICIOUS URLs\n", $self->{top_n};
        $count = 0;
        foreach my $url (sort { $stats->{scan_attempts}{$b} <=> $stats->{scan_attempts}{$a} } 
                         keys %{$stats->{scan_attempts}}) {
            $section .= sprintf "%-50s : %d attempts\n", 
                substr($url, 0, 50), $stats->{scan_attempts}{$url};
            last if ++$count >= $self->{top_n};
        }
        $section .= "\n";
    } else {
        $section .= "No suspicious activity detected.\n\n";
    }
    
    return $section;
}

sub _user_agents {
    my ($self, $stats) = @_;
    
    my $section = '';
    $section .= "USER AGENT STATISTICS\n";
    $section .= "-" x 40 . "\n";
    $section .= sprintf "Unique user agents: %d\n\n", scalar keys %{$stats->{ua_count}};
    
    $section .= "TOP 5 USER AGENTS\n";
    my $count = 0;
    foreach my $ua (sort { $stats->{ua_count}{$b} <=> $stats->{ua_count}{$a} } 
                    keys %{$stats->{ua_count}}) {
        $section .= sprintf "%-40s : %d requests\n", 
            substr($ua, 0, 40), $stats->{ua_count}{$ua};
        last if ++$count >= 5;
    }
    $section .= "\n";
    
    return $section;
}

sub _footer {
    my $self = shift;
    
    my $footer = '';
    $footer .= "=" x 60 . "\n";
    $footer .= "Analysis complete.\n";
    $footer .= "=" x 60 . "\n";
    
    return $footer;
}

sub _format_bytes {
    my ($self, $bytes) = @_;
    
    if ($bytes < 1024) {
        return "$bytes B";
    } elsif ($bytes < 1024 * 1024) {
        return sprintf("%.2f KB", $bytes / 1024);
    } elsif ($bytes < 1024 * 1024 * 1024) {
        return sprintf("%.2f MB", $bytes / (1024 * 1024));
    } else {
        return sprintf("%.2f GB", $bytes / (1024 * 1024 * 1024));
    }
}

1;

__END__

=head1 NAME

Perl::Log::Analyzer::Reporter - Report generator

=head1 SYNOPSIS

    my $reporter = Perl::Log::Analyzer::Reporter->new(top_n => 10);
    my $report = $reporter->generate($stats);

=head1 DESCRIPTION

Generates formatted reports from log analysis statistics.

=head1 METHODS

=head2 new(%args)

Creates a new reporter instance.

=head2 generate($stats)

Generates a formatted report from statistics.

=cut

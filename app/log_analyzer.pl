#!/usr/bin/env perl

use strict;
use warnings;
use feature 'say';

# Хранилища данных 
my %ip_count;      
my %method_count;  
my %url_count;     
my %status_count;  
my %ua_count;    

my $total_requests = 0;     
my $total_bytes = 0;        

# Дополнительные хранилища для анализа ошибок и безопасности
my %error_urls;          # URL, вызывающие ошибки (4xx, 5xx)
my %error_ips;           # IP, с которых приходят ошибочные запросы
my %suspicious_ips;      # IP с подозрительной активностью
my %scan_attempts;       # Попытки сканирования (подозрительные URL)
my %high_error_rate_ips; # IP с высоким процентом ошибок
my $total_errors = 0;    # Общее количество ошибочных запросов

# Список подозрительных паттернов для обнаружения атак/сканирования
my @suspicious_patterns = (
    qr/\.\.\/|\.\.\\/,                    # Path traversal
    qr/etc\/passwd/,                      # Попытка доступа к passwd
    qr/union\s+select/i,                  # SQL injection
    qr/wp-admin|wp-login/,                # WordPress атаки
    qr/phpmyadmin|mysql|phpinfo/,         # Попытки доступа к админке БД
    qr/\.env|\.git|\.svn/,                # Попытки доступа к системным файлам
    qr/<script|javascript:|onerror=/i,    # XSS попытки
    qr/bin\/bash|cmd\.exe|powershell/i,   # Командные интерпретаторы
    qr/\.\.\%5c|\.\.\%2f/i,               # URL encoded path traversal
    qr/\%00|null/i,                       # Null byte injection
    qr/exec|eval|system|passthru/i,       # PHP код execution
);

# Список подозрительных User-Agents (сканеры, боты)
my @suspicious_ua_patterns = (
    qr/nmap|nikto|sqlmap|nessus|acunetix/i,
    qr/curl|wget|python-requests|perl|ruby/i,
    qr/winhttp|httpclient/i,
    qr/\(\);|masscan|zgrab/i,
);

my $log_file = shift @ARGV || 'access.log';
unless (-e $log_file) {
    die "Ошибка: Файл '$log_file' не найден!\n";
}
unless (-r $log_file) {
    die "Ошибка: Нет прав на чтение файла '$log_file'!\n";
}

say "Анализирую файл: $log_file";

open(my $fh, '<', $log_file) or die "Не могу открыть файл '$log_file': $!";

while (my $line = <$fh>) {
    chomp $line;
    $total_requests++;
    
    if ($line =~ /^(\S+) \S+ \S+ \[(.*?)\] "(\S+) (\S+) \S+" (\d{3}) (\d+) "([^"]*)" "([^"]*)"$/) {
        
        my $ip = $1;           
        my $date = $2;         
        my $method = $3;       
        my $url = $4;          
        my $status = $5;       
        my $bytes = $6;        
        my $referer = $7;      
        my $user_agent = $8;   
        
        $ip_count{$ip}++;
        $method_count{$method}++;
        $url_count{$url}++;
        $status_count{$status}++;
        $ua_count{$user_agent}++ if $user_agent;
        $total_bytes += $bytes if $bytes;
        
        # === АНАЛИЗ ОШИБОК ===
        if ($status >= 400) {
            $total_errors++;
            $error_urls{$url}++;
            $error_ips{$ip}++;
            
            # Отслеживаем IP с высоким процентом ошибок (будет рассчитано позже)
            $high_error_rate_ips{$ip}++;
        }
        
        # Проверка на подозрительные URL 
        my $is_suspicious = 0;
        foreach my $pattern (@suspicious_patterns) {
            if ($url =~ $pattern) {
                $suspicious_ips{$ip}++;
                $scan_attempts{$url}++;
                $is_suspicious = 1;
                last;
            }
        }
        
        # Проверка на подозрительные User-Agents
        foreach my $pattern (@suspicious_ua_patterns) {
            if ($user_agent =~ $pattern) {
                $suspicious_ips{$ip}++;
                $scan_attempts{$url}++;
                $is_suspicious = 1;
                last;
            }
        }
        
        # Проверка на слишком частые запросы от одного IP 
        # Это будет рассчитано после полного анализа        
    } else {
        warn "не удалось распарсить строку: $line\n";
    }
}

say "всего строк в файле: $total_requests";

close($fh);

# Определяем IP с высоким процентом ошибок (> 50% запросов с ошибками)
my %high_error_ips_final;
foreach my $ip (keys %high_error_rate_ips) {
    my $error_count = $high_error_rate_ips{$ip};
    my $total_ip_requests = $ip_count{$ip} || 1;
    my $error_percentage = ($error_count / $total_ip_requests) * 100;
    if ($error_percentage > 50 && $error_count > 10) {  # Более 50% ошибок и минимум 10 ошибок
        $high_error_ips_final{$ip} = $error_percentage;
    }
}

say "всего запросов: $total_requests";
say "всего передано данных: " . format_bytes($total_bytes) . "\n";

say "--- топ 10 ip по кол-ву запросов ---";
my $count = 0;
foreach my $ip (sort { $ip_count{$b} <=> $ip_count{$a} } keys %ip_count) {
    printf "%-15s : %d запросов\n", $ip, $ip_count{$ip};
    last if ++$count >= 10;
}
say "";

say "--- статистика http запросов  ---";
foreach my $method (sort keys %method_count) {
    printf "%-10s : %d запросов\n", $method, $method_count{$method};
}
say "";

say "--- топ 10 url по кол-ву запросов ---";
$count = 0;
foreach my $url (sort { $url_count{$b} <=> $url_count{$a} } keys %url_count) {
    printf "%-30s : %d запросов\n", $url, $url_count{$url};
    last if ++$count >= 10;
}
say "";

say "--- статистика кодов ответа ---";
foreach my $status (sort keys %status_count) {
    my $percentage = ($status_count{$status} / $total_requests) * 100;
    printf "%-3s : %d запросов (%.1f%%)\n", $status, $status_count{$status}, $percentage;
}
say "";

# === ВЫВОД АНАЛИЗА ОШИБОК ===
say "-" x 30;
say "--- АНАЛИЗ ОШИБОК ---";
say "-" x 30;
say "всего ошибочных запросов (4xx, 5xx): $total_errors";
my $error_percentage = $total_requests ? ($total_errors / $total_requests) * 100 : 0;
printf "процент ошибок: %.2f%%\n", $error_percentage;
say "";

say "--- топ 10 url с наибольшим количеством ошибок ---";
$count = 0;
foreach my $url (sort { $error_urls{$b} <=> $error_urls{$a} } keys %error_urls) {
    my $error_count = $error_urls{$url};
    my $total_url_requests = $url_count{$url} || 1;
    my $error_rate = ($error_count / $total_url_requests) * 100;
    printf "%-40s : %d ошибок (%.1f%% от запросов к этому url)\n", 
        substr($url, 0, 40), $error_count, $error_rate;
    last if ++$count >= 10;
}
say "";

say "--- топ 10 ip с наибольшим количеством ошибок ---";
$count = 0;
foreach my $ip (sort { $error_ips{$b} <=> $error_ips{$a} } keys %error_ips) {
    my $error_count = $error_ips{$ip};
    my $total_ip_requests = $ip_count{$ip} || 1;
    my $error_rate = ($error_count / $total_ip_requests) * 100;
    printf "%-15s : %d ошибок (%.1f%% от запросов с этого ip)\n", 
        $ip, $error_count, $error_rate;
    last if ++$count >= 10;
}
say "";

if (keys %high_error_ips_final) {
    say "--- IP с высоким процентом ошибок (>50% и >10 ошибок) ---";
    foreach my $ip (sort { $high_error_ips_final{$b} <=> $high_error_ips_final{$a} } keys %high_error_ips_final) {
        my $error_rate = $high_error_ips_final{$ip};
        my $error_count = $error_ips{$ip};
        my $total_requests_ip = $ip_count{$ip};
        printf "%-15s : %.1f%% ошибок (%d из %d запросов)\n", 
            $ip, $error_rate, $error_count, $total_requests_ip;
    }
    say "";
}

say "-" x 30;
say "--- анализ безопасности ---";
say "-" x 30;

if (keys %suspicious_ips) {
    say "--- топ 10 подозрительных IP (попытки взлома/сканирование) ---";
    $count = 0;
    foreach my $ip (sort { $suspicious_ips{$b} <=> $suspicious_ips{$a} } keys %suspicious_ips) {
        my $suspicious_count = $suspicious_ips{$ip};
        my $total_ip_requests = $ip_count{$ip} || 1;
        my $suspicious_percentage = ($suspicious_count / $total_ip_requests) * 100;
        printf "%-15s : %d подозрительных запросов (%.1f%% от всех запросов ip)\n", 
            $ip, $suspicious_count, $suspicious_percentage;
        last if ++$count >= 10;
    }
    say "";
    
    say "--- топ 10 подозрительных URL (попытки атак) ---";
    $count = 0;
    foreach my $url (sort { $scan_attempts{$b} <=> $scan_attempts{$a} } keys %scan_attempts) {
        printf "%-50s : %d попыток\n", substr($url, 0, 50), $scan_attempts{$url};
        last if ++$count >= 10;
    }
    say "";
    
    # Статистика по типам подозрительной активности
    my %attack_types;
    foreach my $url (keys %scan_attempts) {
        foreach my $pattern (@suspicious_patterns) {
            if ($url =~ $pattern) {
                my $type = "";
                if ($pattern =~ /etc\/passwd/) { $type = "Path Traversal (passwd)"; }
                elsif ($pattern =~ /union\s+select/i) { $type = "SQL Injection"; }
                elsif ($pattern =~ /wp-admin|wp-login/) { $type = "WordPress Attack"; }
                elsif ($pattern =~ /phpmyadmin|mysql/) { $type = "Database Access"; }
                elsif ($pattern =~ /\.env|\.git|\.svn/) { $type = "Config File Access"; }
                elsif ($pattern =~ /<script|javascript:/i) { $type = "XSS Attempt"; }
                elsif ($pattern =~ /bin\/bash|cmd\.exe/) { $type = "Command Execution"; }
                elsif ($pattern =~ /\.\.\/|\.\.\\|\.\.\%5c/) { $type = "Path Traversal"; }
                else { $type = "Other Suspicious Activity"; }
                $attack_types{$type} += $scan_attempts{$url};
                last;
            }
        }
    }
    
    if (keys %attack_types) {
        say "--- типы обнаруженных атак ---";
        foreach my $type (sort { $attack_types{$b} <=> $attack_types{$a} } keys %attack_types) {
            printf "%-30s : %d попыток\n", $type, $attack_types{$type};
        }
        say "";
    }
} else {
    say "подозрительной активности не обнаружено.\n";
}

# Анализ частоты запросов от IP 
my %high_frequency_ips;
foreach my $ip (keys %ip_count) {
    if ($ip_count{$ip} > 100) {  
        $high_frequency_ips{$ip} = $ip_count{$ip};
    }
}

if (keys %high_frequency_ips) {
    say "--- IP с высоким количеством запросов (потенциальный DoS/сканер) ---";
    $count = 0;
    foreach my $ip (sort { $high_frequency_ips{$b} <=> $high_frequency_ips{$a} } keys %high_frequency_ips) {
        printf "%-15s : %d запросов (%.1f%% от всех запросов)\n", 
            $ip, $high_frequency_ips{$ip}, 
            ($high_frequency_ips{$ip} / $total_requests) * 100;
        last if ++$count >= 10;
    }
    say "";
}

say "--- уникальные user agents ---";
say "всего уникальных клиентов: " . scalar keys %ua_count;

say "\nтоп 5 user-Agents:";
$count = 0;
foreach my $ua (sort { $ua_count{$b} <=> $ua_count{$a} } keys %ua_count) {
    printf "%-40s : %d запросов\n", substr($ua, 0, 40), $ua_count{$ua};
    last if ++$count >= 5;
}

say "\n" . "_" x 30;
say "анализ завершен.";
say "_" x 30;

sub format_bytes {
    my $bytes = shift;
    
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
use strict;
use warnings;

my $output_file = 'access.log';
open(my $fh, '>', $output_file) or die "Cannot open $output_file: $!";

# Возможные значения для генерации
my @ips = ('192.168.1.1', '10.0.0.1', '172.16.0.1', '8.8.8.8', '1.1.1.1');
my @methods = ('GET', 'POST', 'PUT', 'DELETE');
my @urls = ('/index.html', '/about', '/api/users', '/images/logo.png', '/admin', '/products', '/cart');
my @statuses = (200, 200, 200, 200, 301, 404, 500);  # 200 чаще, ошибки реже
my @user_agents = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)',
    'curl/7.68.0',
    'Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0'
);

# Генерируем 1000 записей
for (1..1000) {
    my $ip = $ips[rand @ips];
    my $method = $methods[rand @methods];
    my $url = $urls[rand @urls];
    my $status = $statuses[rand @statuses];
    my $user_agent = $user_agents[rand @user_agents];
    
    # Генерируем дату: последние 30 дней
    my $days_ago = int(rand(30));
    my $date = sprintf "[%02d/%s/%d:%02d:%02d:%02d +0000]",
        int(rand(28)) + 1,
        ('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec')[rand 12],
        2024 + int(rand(2)),
        int(rand(24)),
        int(rand(60)),
        int(rand(60));
    
    my $bytes = int(rand(10000)) + 100;
    
    my $log_line = qq($ip - - $date "$method $url HTTP/1.1" $status $bytes "-" "$user_agent"\n);
    print $fh $log_line;
}

close $fh;
print "Generated 1000 log entries to $output_file\n";
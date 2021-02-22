package PVE::LXC::Setup::NixOS;

use strict;
use warnings;

use File::Path 'make_path';

use PVE::LXC::Setup::Base;

use base qw(PVE::LXC::Setup::Base);

sub new {
    my ($class, $conf, $rootdir) = @_;

    #my $version = PVE::Tools::file_read_firstline("$rootdir/nix_pve_interface");
    my $version = "whatever";
    die "unable to read version info\n" if !defined($version);
    #if ($version =~ /^gentoo base system release (.*)$/i) {
    #    $version = $1;
    #} else {
    #    die "unrecognized nixos version: $version\n";
    #}

    my $self = { conf => $conf, rootdir => $rootdir, version => 0 };

    $conf->{ostype} = "nixos";

    return bless $self, $class;

}

sub devttydir {
    return '';
}

sub template_fixup {
    my ($self, $conf) = @_;
    $self->setup_securetty($conf);
}

sub setup_init {
    my ($self, $conf) = @_;
}

sub setup_network {
    my ($self, $conf) = @_;

    # Gentoo's /etc/conf.d/net is supposed to only contains variables, but is
    # in fact sourced by a shell, so reading out existing modules/config values
    # is pretty inconvenient.
    # We SHOULD check for whether iproute2 or ifconfig is already being used,
    # but for now we just assume ifconfig (since they also state iproute2 might
    # not be available in a default setup, though the templates usually do have
    # it installed - we might just get away with an if/else clause to insert
    # ifconfig/iproute2 syntax as needed, that way we don't need to parse this
    # file even to support both...)

    my %modules = (ifconfig => 1);

    my $data = '';
    my %up;

    my $filename = "/pve_net";

    foreach my $k (keys %$conf) {
	next if $k !~ m/^net(\d+)$/;
	my $d = PVE::LXC::Config->parse_lxc_network($conf->{$k});
	my $name = $d->{name};
	next if !$name;

	my $has_ipv4 = 0;
	my $has_ipv6 = 0;

	my $config = '';
	my $routes = '';

	if (defined(my $ip = $d->{ip})) {
	    if ($ip eq 'dhcp') {
		#$modules{dhclient} = 1; # Well, we could...
		#$config .= "dhcp\n";
		#$up{$name} = 1;
	    } elsif ($ip ne 'manual') {
		$has_ipv4 = 1;
		$config .= "ip addr add $ip dev $name\nsleep 1\n";
		$up{$name} = 1;
	    }
	}
	if (defined(my $gw = $d->{gw})) {
	    #if ($has_ipv4 && !PVE::Network::is_ip_in_cidr($gw, $d->{ip}, 4)) {
	#	$routes .= "-host $gw dev $name\n";
	    #}
	    $routes .= "ip route add default via $gw dev $name\n";
	    $up{$name} = 1;
	}

	#if (defined(my $ip = $d->{ip6})) {
	#    if ($ip eq 'dhcp') {
		# FIXME: The default templates seem to only ship busybox' udhcp
		# client which means we're in the same boat as alpine linux.
		# They also don't provide dhcpv6-only at all - for THAT however
		# there are patches from way back in 2013 (bug#450326 on
		# gentoo.org's netifrc)... but whatever, # that's only 10 years
		# after the RFC3315 release (DHCPv6).
		#
		# So no dhcpv6(-only) setups here for now.

		#$modules{dhclientv6} = 1;
		#$config .= "dhcpv6\n";
		#$up{$name} = 1;
	#    } elsif ($ip ne 'manual') {
	#	$has_ipv6 = 1;
	#	$config .= "$ip\n";
	#	$up{$name} = 1;
	#    }
	#}
	#if (defined(my $gw = $d->{gw6})) {
	#    if ($has_ipv6 && !PVE::Network::is_ip_in_cidr($gw, $d->{ip6}, 4)) {
	#	$routes .= "-6 -host $gw dev $name\n";
	#    }
	#    $routes .= "-6 default gw $gw\n";
	#    $up{$name} = 1;
	#}

	chomp $config;
	chomp $routes;
	$data .= "$config\n" if $config;
	$data .= "$routes\n" if $routes;
    }

    $data = "#!/bin/sh\n" . $data;

    # We replace the template's default file...
    $self->ct_modify_file($filename, $data, replace => 1);

    #foreach my $iface (keys %up) {
	#$self->ct_symlink("net.lo", "/etc/init.d/net.$iface");
    #}
}

sub remove_pve_sections {
    my ($data) = @_;

    my $head = "# --- BEGIN PVE ---";
    my $tail = "# --- END PVE ---";

    # Remove the sections enclosed with the above headers and footers.
    # from a line (^) starting with '\h*$head'
    # to a line (the other ^) starting with '\h*$tail' up to including that
    # line's end (.*?$).
    return $data =~ s/^\h*\Q$head\E.*^\h*\Q$tail\E.*?$//rgms;
}

sub update_hosts_nixos {
    my ($self, $hostip, $oldname, $newname, $searchdomains) = @_;

    my $hosts_fn = '/pve_hosts';
    return if $self->ct_is_file_ignored($hosts_fn);

    my $namepart = ($newname =~ s/\..*$//r);

    my $all_names = '';
    if ($newname =~ /\./) {
        $all_names .= "$newname $namepart";
    } else {
        foreach my $domain (PVE::Tools::split_list($searchdomains)) {
            $all_names .= ' ' if $all_names;
            $all_names .= "$newname.$domain";
        }
        $all_names .= ' ' if $all_names;
        $all_names .= $newname;
    }

    # Prepare section:
    my $section = '';

    my $lo4 = "127.0.0.1 localhost.localnet localhost\n";
    my $lo6 = "::1 localhost.localnet localhost\n";
    if ($self->ct_file_exists($hosts_fn)) {
        my $data = $self->ct_file_get_contents($hosts_fn);
        # don't take localhost entries within our hosts sections into account
        $data = remove_pve_sections($data);

        # check for existing localhost entries
        $section .= $lo4 if $data !~ /^\h*127\.0\.0\.1\h+/m;
        $section .= $lo6 if $data !~ /^\h*::1\h+/m;
    } else {
        $section .= $lo4 . $lo6;
    }

    if (defined($hostip)) {
        $section .= "$hostip $all_names\n";
    } elsif ($namepart ne 'localhost') {
        $section .= "127.0.1.1 $all_names\n";
    } else {
        $section .= "127.0.1.1 $namepart\n";
    }

    $self->ct_modify_file($hosts_fn, $section);
}

sub set_hostname {
    my ($self, $conf) = @_;

    my $hostname = $conf->{hostname} || 'localhost';

    my $namepart = ($hostname =~ s/\..*$//r);

    my $hostname_fn = "/pve_hostname"; # ew

    $self->ct_file_set_contents($hostname_fn, "");

    my $oldname = 'localhost';
    my $fh = $self->ct_open_file_read($hostname_fn);
    while (defined(my $line = <$fh>)) {
        chomp $line;
        next if $line =~ /^\s*(#.*)?$/;
        if ($line =~ /^\s*hostname=("[^"]*"|'[^']*'|\S*)\s*$/) {
            $oldname = $1;
            last;
        }
    }
    $fh->close();

    my ($ipv4, $ipv6) = PVE::LXC::get_primary_ips($conf);
    my $hostip = $ipv4 || $ipv6;

    my ($searchdomains) = $self->lookup_dns_conf($conf);

    $self->update_hosts_nixos($hostip, $oldname, $hostname, $searchdomains); # set contents or something idunno

    $self->ct_file_set_contents($hostname_fn, "hostname=\"$namepart\"\n");
}


my $replacepw  = sub {
    my ($self, $file, $user, $epw, $shadow) = @_;

    my $tmpfile = "$file.$$";

    eval  {
        my $src = $self->ct_open_file_read($file) ||
            die "unable to open file '$file' - $!";

        my $st = $self->ct_stat($src) ||
            die "unable to stat file - $!";

        my $dst = $self->ct_open_file_write($tmpfile) ||
            die "unable to open file '$tmpfile' - $!";

        # copy owner and permissions
        chmod $st->mode, $dst;
        chown $st->uid, $st->gid, $dst;

        my $last_change = int(time()/(60*60*24));

        while (defined (my $line = <$src>)) {
            if ($shadow) {
                $line =~ s/^${user}:[^:]*:[^:]*:/${user}:${epw}:${last_change}:/;
            } else {
                $line =~ s/^${user}:[^:]*:/${user}:${epw}:/;
            }
            print $dst $line;
        }

        $src->close() || die "close '$file' failed - $!\n";
        $dst->close() || die "close '$tmpfile' failed - $!\n";
    };
    if (my $err = $@) {
        $self->ct_unlink($tmpfile);
    } else {
        $self->ct_rename($tmpfile, $file);
        $self->ct_unlink($tmpfile); # in case rename fails
    }
};

sub set_user_password {
    my ($self, $conf, $user, $opt_password) = @_;
    my $pwfile = "/pve_passwd";
    return if !$self->ct_file_exists($pwfile);
    my $shadow = "/pve_shadow";

    if (defined($opt_password)) {
        if ($opt_password !~ m/^\$(?:1|2[axy]?|5|6)\$[a-zA-Z0-9.\/]{1,16}\$[a-zA-Z0-9.\/]+$/) {
            my $time = substr (Digest::SHA::sha1_base64 (time), 0, 8);
            $opt_password = crypt(encode("utf8", $opt_password), "\$6\$$time\$");
        };
    } else {
        $opt_password = '*';
    }

    if ($self->ct_file_exists($shadow)) {
        &$replacepw ($self, $shadow, $user, $opt_password, 1);
        &$replacepw ($self, $pwfile, $user, 'x');
    } else {
        &$replacepw ($self, $pwfile, $user, $opt_password);
    }
}

sub set_user_authorized_ssh_keys {
    my ($self, $conf, $user, $ssh_keys) = @_;

    $self->ct_modify_file("/pve_authorized_keys", $ssh_keys, perms => 0700);

}

sub set_dns {
    my ($self, $conf) = @_;

    my ($searchdomains, $nameserver) = $self->lookup_dns_conf($conf);

    my $data = '';

    $data .= "search " . join(' ', PVE::Tools::split_list($searchdomains)) . "\n"
        if $searchdomains;

    foreach my $ns ( PVE::Tools::split_list($nameserver)) {
        $data .= "nameserver $ns\n";
    }

    $self->ct_modify_file("/pve_resolvconf", $data, replace => 1);
}

sub set_timezone {
    my ($self, $conf) = @_;

    my $zoneinfo = $conf->{timezone};

    return if !defined($zoneinfo);

    my $tz_path = "/usr/share/zoneinfo/$zoneinfo";

    #if ($zoneinfo eq 'host') {
    #    $tz_path = $self->{host_localtime};
    #}

    #return if abs_path('/etc/localtime') eq $tz_path;

    #if ($self->ct_file_exists($tz_path)) {
    #    my $tmpfile = "localtime.$$.new.tmpfile";
    #    $self->ct_symlink($tz_path, $tmpfile);
    #    $self->ct_rename($tmpfile, "/etc/localtime");
    #} else {
    #    warn "container does not have $tz_path, timezone can not be modified\n";
    #}
}

1;

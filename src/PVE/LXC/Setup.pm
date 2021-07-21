package PVE::LXC::Setup;

use strict;
use warnings;
use POSIX;
use PVE::Tools;

use Cwd 'abs_path';

use PVE::LXC::Setup::Debian;
use PVE::LXC::Setup::Ubuntu;
use PVE::LXC::Setup::CentOS;
use PVE::LXC::Setup::Fedora;
use PVE::LXC::Setup::SUSE;
use PVE::LXC::Setup::ArchLinux;
use PVE::LXC::Setup::Alpine;
use PVE::LXC::Setup::Gentoo;
use PVE::LXC::Setup::NixOS;
use PVE::LXC::Setup::Devuan;

my $plugins = {
    debian    => 'PVE::LXC::Setup::Debian',
    devuan    => 'PVE::LXC::Setup::Devuan',
    ubuntu    => 'PVE::LXC::Setup::Ubuntu',
    centos    => 'PVE::LXC::Setup::CentOS',
    fedora    => 'PVE::LXC::Setup::Fedora',
    opensuse  => 'PVE::LXC::Setup::SUSE',
    archlinux => 'PVE::LXC::Setup::ArchLinux',
    alpine    => 'PVE::LXC::Setup::Alpine',
    gentoo    => 'PVE::LXC::Setup::Gentoo',
    nixos     => 'PVE::LXC::Setup::NixOS',
};

# a map to allow supporting related distro flavours
my $plugin_alias = {
    arch => 'archlinux',
    sles => 'opensuse',
    'opensuse-leap' => 'opensuse',
    'opensuse-tumbleweed' => 'opensuse',
};

my $autodetect_type = sub {
    my ($self, $rootdir, $os_release) = @_;

    if (my $id = $os_release->{ID}) {
	return $id if $plugins->{$id};
	return $plugin_alias->{$id} if $plugin_alias->{$id};
	warn "unknown ID '$id' in /etc/os-release file, trying fallback detection\n";
    }

    # fallback compatibility checks

    my $lsb_fn = "$rootdir/etc/lsb-release";
    if (-f $lsb_fn) {
	my $data =  PVE::Tools::file_get_contents($lsb_fn);
	if ($data =~ m/^DISTRIB_ID=Ubuntu$/im) {
	    return 'ubuntu';
	}
    }

    if (-f "$rootdir/etc/debian_version") {
	return "debian";
    } elsif (-f "$rootdir/etc/devuan_version") {
	return "devuan";
    } elsif (-f  "$rootdir/etc/SuSE-brand" || -f "$rootdir/etc/SuSE-release") {
	return "opensuse";
    } elsif (-f  "$rootdir/etc/fedora-release") {
	return "fedora";
    } elsif (-f  "$rootdir/etc/centos-release" || -f "$rootdir/etc/redhat-release") {
	return "centos";
    } elsif (-f  "$rootdir/etc/arch-release") {
	return "archlinux";
    } elsif (-f  "$rootdir/etc/alpine-release") {
	return "alpine";
    } elsif (-f  "$rootdir/etc/gentoo-release") {
	return "gentoo";
    } elsif (-d  "$rootdir/nix") {
        return "nixos";
    } elsif (-f "$rootdir/etc/os-release") {
	die "unable to detect OS distribution\n";
    } else {
	warn "/etc/os-release file not found and autodetection failed, falling back to 'unmanaged'\n";
	return "unmanaged";
    }
};

sub new {
    my ($class, $conf, $rootdir, $type) = @_;

    die "no root directory\n" if !$rootdir || $rootdir eq '/';

    my $self = bless { conf => $conf, rootdir => $rootdir};

    my $os_release = $self->get_ct_os_release();

    if ($conf->{ostype} && $conf->{ostype} eq 'unmanaged') {
	return $self;
    } elsif (!defined($type)) {
	# try to autodetect type
	$type = &$autodetect_type($self, $rootdir, $os_release);
	my $expected_type = $conf->{ostype} || $type;

	if ($type ne $expected_type) {
	    warn "WARNING: /etc not present in CT, is the rootfs mounted?\n"
		if ! -e "$rootdir/etc";
	    warn "got unexpected ostype ($type != $expected_type)\n"
	}
    }

    if ($type eq 'unmanaged') {
	$conf->{ostype} = $type;
	return $self;
    }

    my $plugin_class = $plugins->{$type} ||
	"no such OS type '$type'\n";

    my $plugin = $plugin_class->new($conf, $rootdir, $os_release);
    $self->{plugin} = $plugin;
    $self->{in_chroot} = 0;

    # Cache some host files we need access to:
    $plugin->{host_resolv_conf} = PVE::INotify::read_file('resolvconf');
    $plugin->{host_localtime} = abs_path('/etc/localtime');

    # pass on user namespace information:
    my ($id_map, $rootuid, $rootgid) = PVE::LXC::parse_id_maps($conf);
    if (@$id_map) {
	$plugin->{id_map} = $id_map;
	$plugin->{rootuid} = $rootuid;
	$plugin->{rootgid} = $rootgid;
    }
    
    return $self;
}

# Forks into a chroot and executes $sub
sub protected_call {
    my ($self, $sub) = @_;

    # avoid recursion:
    return $sub->() if $self->{in_chroot};

    pipe(my $res_in, my $res_out) or die "pipe failed: $!\n";

    my $child = fork();
    die "fork failed: $!\n" if !defined($child);

    if (!$child) {
	close($res_in);
	# avoid recursive forks
	$self->{in_chroot} = 1;
	eval {
	    my $rootdir = $self->{rootdir};
	    chroot($rootdir) or die "failed to change root to: $rootdir: $!\n";
	    chdir('/') or die "failed to change to root directory\n";
	    my $res = $sub->();
	    if (defined($res)) {
		print {$res_out} "$res";
		$res_out->flush();
	    }
	};
	if (my $err = $@) {
	    warn $err;
	    POSIX::_exit(1);
	}
	POSIX::_exit(0);
    }
    close($res_out);
    my $result = do { local $/ = undef; <$res_in> };
    while (waitpid($child, 0) != $child) {}
    if ($? != 0) {
	my $method = (caller(1))[3];
	die "error in setup task $method\n";
    }
    return $result;
}

sub template_fixup {
    my ($self) = @_;

    return if !$self->{plugin}; # unmanaged

    my $code = sub {
	$self->{plugin}->template_fixup($self->{conf});
    };
    $self->protected_call($code);
}
 
sub setup_network {
    my ($self) = @_;

    return if !$self->{plugin}; # unmanaged

    my $code = sub {
	$self->{plugin}->setup_network($self->{conf});
    };
    $self->protected_call($code);
}

sub set_hostname {
    my ($self) = @_;

    return if !$self->{plugin}; # unmanaged

    my $code = sub {
	$self->{plugin}->set_hostname($self->{conf});
    };
    $self->protected_call($code);
}

sub set_dns {
    my ($self) = @_;

    return if !$self->{plugin}; # unmanaged

    my $code = sub {
	$self->{plugin}->set_dns($self->{conf});
    };
    $self->protected_call($code);
}

sub set_timezone {
    my ($self) = @_;

    return if !$self->{plugin}; # unmanaged
    my $code = sub {
	$self->{plugin}->set_timezone($self->{conf});
    };
    $self->protected_call($code);
}

sub setup_init {
    my ($self) = @_;

    return if !$self->{plugin}; # unmanaged

    my $code = sub {
	$self->{plugin}->setup_init($self->{conf});
    };
    $self->protected_call($code);
}

sub set_user_password {
    my ($self, $user, $pw) = @_;

    return if !$self->{plugin}; # unmanaged

    my $code = sub {
	$self->{plugin}->set_user_password($self->{conf}, $user, $pw);
    };
    $self->protected_call($code);
}

sub rewrite_ssh_host_keys {
    my ($self) = @_;

    return if !$self->{plugin}; # unmanaged

    my $conf = $self->{conf};
    my $plugin = $self->{plugin};
    my $rootdir = $self->{rootdir};

    return if ! -d "$rootdir/etc/ssh";

    my $keynames = {
	rsa => 'ssh_host_rsa_key',
	dsa => 'ssh_host_dsa_key',
	ecdsa => 'ssh_host_ecdsa_key', 
	ed25519 => 'ssh_host_ed25519_key',
    };

    my $hostname = $conf->{hostname} || 'localhost';
    $hostname =~ s/\..*$//;
    my $ssh_comment = "root\@$hostname";

    my $keygen_outfunc = sub {
	my $line = shift;

	print "done: $line\n"
	    if $line =~ m/^(?:[0-9a-f]{2}:)+[0-9a-f]{2}\s+\Q$ssh_comment\E$/i ||
	       $line =~ m/^SHA256:[0-9a-z+\/]{43}\s+\Q$ssh_comment\E$/i;
    };

    # Create temporary keys in /tmp on the host
    my $keyfiles = {};
    foreach my $keytype (keys %$keynames) {
	my $basename = $keynames->{$keytype};
	my $file = "/tmp/$$.$basename";
	print "Creating SSH host key '$basename' - this may take some time ...\n";
	my $cmd = ['ssh-keygen', '-f', $file, '-t', $keytype,
		   '-N', '', '-E', 'sha256', '-C', $ssh_comment];
	PVE::Tools::run_command($cmd, outfunc => $keygen_outfunc);
	$keyfiles->{"/etc/ssh/$basename"} = [PVE::Tools::file_get_contents($file), 0600];
	$keyfiles->{"/etc/ssh/$basename.pub"} = [PVE::Tools::file_get_contents("$file.pub"), 0644];
	unlink $file;
	unlink "$file.pub";
    }

    # Write keys out in a protected call

    my $code = sub {
	foreach my $file (keys %$keyfiles) {
	    $plugin->ct_file_set_contents($file, @{$keyfiles->{$file}});
	}
    };
    $self->protected_call($code);
}    

my $container_emulator_path = {
    'amd64' => '/usr/bin/qemu-x86_64-static',
    'arm64' => '/usr/bin/qemu-aarch64-static',
};

sub pre_start_hook {
    my ($self) = @_;

    return if !$self->{plugin}; # unmanaged

    my $host_arch = PVE::Tools::get_host_arch();

    # containers use different architecture names
    if ($host_arch eq 'x86_64') {
	$host_arch = 'amd64';
    } elsif ($host_arch eq 'aarch64') {
	$host_arch = 'arm64';
    } else {
	die "unsupported host architecture '$host_arch'\n";
    }

    my $container_arch = $self->{conf}->{arch};

    $container_arch = 'amd64' if $container_arch eq 'i386'; # always use 64 bit version
    $container_arch = 'arm64' if $container_arch eq 'armhf'; # always use 64 bit version

    my $emul;
    my $emul_data;

    if ($host_arch ne $container_arch) {
	if ($emul = $container_emulator_path->{$container_arch}) {
	    $emul_data = PVE::Tools::file_get_contents($emul, 10*1024*1024) if -f $emul;
	}
    }

    my $code = sub {

	if ($emul && $emul_data) {
	    $self->{plugin}->ct_file_set_contents($emul, $emul_data, 0755);
	}

	# Create /fastboot to skip run fsck
	$self->{plugin}->ct_file_set_contents('/fastboot', '');

	$self->{plugin}->pre_start_hook($self->{conf});
    };
    $self->protected_call($code);
}

sub post_clone_hook {
    my ($self, $conf) = @_;

    $self->protected_call(sub {
	$self->{plugin}->post_clone_hook($conf);
    });
}

sub post_create_hook {
    my ($self, $root_password, $ssh_keys) = @_;

    return if !$self->{plugin}; # unmanaged

    my $code = sub {
	$self->{plugin}->post_create_hook($self->{conf}, $root_password, $ssh_keys);
    };
    $self->protected_call($code);
    $self->rewrite_ssh_host_keys();
}

# os-release(5):
#   (...) a newline-separated list of environment-like shell-compatible
#   variable assignments. (...) beyond mere variable assignments, no shell
#   features are supported (this means variable expansion is explicitly not
#   supported) (...). Variable assignment values must be enclosed in double or
#   single quotes *if* they include spaces, semicolons or other special
#   characters outside of A-Z, a-z, 0-9. Shell special characters ("$", quotes,
#   backslash, backtick) must be escaped with backslashes (...). All strings
#   should be in UTF-8 format, and non-printable characters should not be used.
#   It is not supported to concatenate multiple individually quoted strings.
#   Lines beginning with "#" shall be ignored as comments.
my $parse_os_release = sub {
    my ($data) = @_;
    my $variables = {};
    while (defined($data) && $data =~ /^(.+)$/gm) {
	next if $1 !~ /^\s*([a-zA-Z_][a-zA-Z0-9_]*)=(.*)$/;
	my ($var, $content) = ($1, $2);
	chomp $content;

	if ($content =~ /^'([^']*)'/) {
	    $variables->{$var} = $1;
	} elsif ($content =~ /^"((?:[^"\\]|\\.)*)"/) {
	    my $s = $1;
	    $s =~ s/(\\["'`nt\$\\])/"\"$1\""/eeg;
	    $variables->{$var} = $s;
	} elsif ($content =~ /^([A-Za-z0-9]*)/) {
	    $variables->{$var} = $1;
	}
    }
    return $variables;
};

sub get_ct_os_release {
    my ($self) = @_;

    my $code = sub {
	if (-f '/etc/os-release') {
	    return PVE::Tools::file_get_contents('/etc/os-release');
	} elsif (-f '/usr/lib/os-release') {
	    return PVE::Tools::file_get_contents('/usr/lib/os-release');
	}
	return undef;
    };

    my $data = $self->protected_call($code);

    return &$parse_os_release($data);
}

sub unified_cgroupv2_support {
    my ($self) = @_;

    $self->protected_call(sub {
	$self->{plugin}->unified_cgroupv2_support();
    });
}

1;

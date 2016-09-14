package Process::Watcher;

use constant {
	PRECISION_WAIT => 0.009,
};

use strict;
use warnings;
use English qw(-no_match_vars);

use File::Slurp qw( read_file );
use Scalar::Util qw( looks_like_number );
use POSIX qw(ceil);
use Time::HiRes ();
# 1 filter by pid
# 2 filter by ppid
# 3 filter by stime

sub _procfs_getinfo ($) {
	my $pid = shift(@_);
	if ( my $contents = read_file( "/proc/$pid", err_mode => "quiet" ) ) {
		my @fields = split(qr/\s+/, $contents);
		# 22 is start time in ticks/jiffies. 14 is utime, and 15 is stime, also in ticks/jiffies.
		return (
			pid => $pid,
			ppid => $fields[4],
			"time" => $fields[14] + $fields[15],
			# todo check kernel rev: <2.6 = jiffies; else ticks
			start => $fields[22],
		);
	}
	return;
}

sub _probe_procfs {
	my $pid = shift(@_);
	if ( defined $pid ) {
		my $valid = -d "/proc/$pid";
		my %info = _procfs_getinfo($pid);
		# todo verify that parent PID works
		foreach my $field (qw( time start )) {
			$valid &&= $info{$field} && looks_like_number($info{$field}) && $info{$field} > 0;
		}
		return $valid;
	}
	else {
		return _probe_procfs($PROCESS_ID) && _probe_procfs(getppid()) && _probe_procfs(1);
	}
}

my $HAVE_PROCFS;
sub _high_precision_starttime ($) {
	my ( $info ) = @_;
	if ( $HAVE_PROCFS //= _probe_procfs() ) {
		my %procinfo = _procfs_getinfo($info->pid);
		_assert($procinfo{ppid} == $info->ppid);
		return ( $procinfo{start}, $procinfo{time}, 1 );
	}
	else {
		my $proc = P9Y::ProcessTable::Process->process($info->pid);
		_assert($proc->ppid == $info->ppid);
		return ( $proc->start, $proc->time );
	}
}

sub _read_procs {
	my %args = @_;
	my %returnvalue; # Perfect hash with pid count?

	return %returnvalue;
}

sub children_exist ($@) {
	my $parent = shift(@_);
	return _read_procs(
		parent => $parent,
		pids => \@_,
	);
}

sub processes_exist ($;@) {
	return _read_procs(
		pids => \@_,
	);
}

sub child_exists ($$) {
	return _read_procs(
		parent => $_[0],
		pids => [$_[1]],
	);
}

sub process_exists ($) {
	return _read_procs(
		pids => [$_[0]],
	);
}

# STATIC METHODS:
sub create ($;%) {
	my ( $class, %args ) = @_;
	my $sub = delete($args{sub}) || \&CORE::fork;
	_valid_args(%args);
	# TODO signal tx?
	local $OS_ERROR;
	my $rv = $sub->();
	undef $sub;
	if ( $rv > 0 ) {
		return $class->new(%args);
	}
	elsif ( $rv < 0 ) {
		die "Something went wrong while running process-creation sub; it returned $rv. Errno: $OS_ERROR";
	}
	return;
}

# CLASS METHODS:
sub new ($;%) {
	my ( $class, %args ) = @_;
	_valid_args(%args);
	# We go to some trouble to try to get a stable UID for the process being
	# watched. Since it's a child process, we can assume (if we're single-
	# -threaded) that its PPID won't change. If we block signals, we can
	# prevent it from being reaped via CHLD handlers. That leaves the UID itself:
	# start time is held internally in jiffies or clock ticks, so it can
	# be used for unique identification, provided we wait at least a clock-
	# -tick/jiffy before returning, in order to verify that a reap/create event
	# that takes place just after watcher construction can't (in massively rare
	# pid-wraparound coincidence cases) replace the target process with another
	# one that has both the same PID and the same start time. The problematic
	# case becomes much less massively rare, however, in cases where the process
	# start time is stored in full seconds (this code falls back to the cross-
	# -platform, full-second-precision start time supplied by ProcessTable on
	# any OS that doesn't have a compliant /proc filesystem, at least for now).
	# In those low-precision cases, we provide the option to wait up to a second
	# for the elapsed time on the process to change.
	_signal_tx {
		my $t0 = CORE::time();
		my $info = _assert_child($args{pid});
		my $start = $info->start;
		
		if ( $start > $t0 ) { # The low-precision start timer should never wrap.
			die "Something is horribly wrong";
		}
		elsif ( $start == $t0 ) {
			# Only do high-resolution start-time checking if the child was
			# started really recently.
			my ( $elapsed, $highprecision );
			( $start, $elapsed, $highprecision ) = _high_precision_starttime($info);
			# We can't get "now" in jiffies, so, if wait is set, we wait
			# until at least one jiffy has elapsed on the process's total etime.

			# In high-precision mode, I'm reasonably sure that elapsed time and
			# start time are either in the same increment, or that etime is in
			# larger increments than starttime.
			if ( $highprecision ) {
				Time::HiRes::sleep(0); # Superstition.
				while ( 1 ) {
					my $curelapsed = (_high_precision_starttime($info))[1];
					# Jiffy clocks can wrap around, so we have to cope with that as
					# well, hence the >= check. The check function itself will assert
					# that the parent PID stays the same.
					if ( $elapsed > $curelapsed ) {
						$elapsed = $curelapsed;
					}
					elsif ( $args{wait} && $elapsed == $curelapsed ) {
						Time::HiRes::sleep(PRECISION_WAIT);
					}
					else {
						last;
					}
				}
			}
			elsif ( $args{wait} ) { # Assume "start" is in epoch seconds.
				Time::HiRes::sleep(0); # Superstition.
				# Sleep until the second boundary gets crossed.
				# TODO which half of the below gets eval'd first?
				# TODO for non-child watchers, the below will have to cope with pidchange during the loop.
				while ( _assert_child($args{pid})->start == CORE::time() ) {
					Time::HiRes::sleep(PRECISION_WAIT);
				}
			}

			$args{uid} = $start;
		}
	};
	return bless($class, \%args);
}



#   instance:


# - new  ( childwatch y/n )
# 	reads starttime into uid, -> global
# 	optionally sets up child watcher
# - _child_watcher:
# 	- signal tx
# 	- exists{skip kill 0} && waitpid
# - _maybeloadProcess::Table
# - reaped_by -> CHLD or other
# - kill $SIG: identity-safe version of kill; wraps in signal blocken
# - setup_child_watcher
# 	maybe uses SigAction? Or XSIG? falls back to default SIG
# - finish( fatal y/n, timeout )
# - exists: local state -> kill 0 -> is_child(self.pid)
# - DESTROY ( finish(n, 0), but warns/logs )


1;
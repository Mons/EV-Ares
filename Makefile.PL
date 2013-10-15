use 5.008008;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
	NAME              => 'EV::Ares',
	VERSION_FROM      => 'lib/EV/Ares.pm', # finds $VERSION
	PREREQ_PM         => { EV => 4 }, # e.g., Module::Name => 1.1
	ABSTRACT_FROM  => 'lib/EV/Ares.pm', # retrieve abstract from module
	AUTHOR         => 'Mons Anderson <mons@cpan.org>',
	LIBS              => ['-lcares'], # e.g., '-lm'
	DEFINE            => '', # e.g., '-DHAVE_SOMETHING'
	'CONFIGURE' => sub {
		require EV::MakeMaker;
		return {EV::MakeMaker::ev_args(
			INC               => '-I. -I./evares/src', # e.g., '-I. -I/usr/include/other'
		)};
	},
	# OBJECT            => '$(O_FILES)', # link all the C files too
);

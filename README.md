[![Build Status](https://travis-ci.org/dgoulet/torsocks.png)](https://travis-ci.org/dgoulet/torsocks)

What is torsocks?
-----------------

Torsocks allows you to use most applications in a safe way with Tor. It ensures
that DNS requests are handled safely and explicitly rejects any traffic other
than TCP from the application you're using.

Torsocks is an ELF shared library that is loaded before all others. The
library overrides every needed Internet communication libc function calls such
as connect(2) or gethostbyname(3).

BE ADVISE: It uses the LD\_PRELOAD mechanism (man ld.so.8) which means that if
the application is not using the libc or for instance uses raw syscalls,
torsocks will be useless and the traffic will not go through Tor.

This process is transparent to the user and if torsocks detects any
communication that can't go through the Tor network such as UDP traffic, for
instance, the connection is denied. If, for any reason, there is no way for
torsocks to provide the Tor anonymity guarantee to your application, torsocks
will force the application to quit and stop everything.

Requirements
-----------------

	- autoconf
	- automake
	- libtool
	- gcc

Installation
-----------------

    $ ./autogen.sh
    $ ./configure
    $ make
    $ sudo make install

If you are compiling it from the git repository, run ./autogen.sh before the
configure script.

Using torsocks
--------------

Once you have installed torsocks, just launch it like so:

    $ torsocks [application]

So, for example you can use ssh to a some.ssh.com by doing:

    $ torsocks ssh username@some.ssh.com

You can use the torsocks library without the script provided:

    $ LD_PRELOAD=/full/path/to/libtorsocks.so your_app

For more details, please see the torsocks.1, torsocks.8 and torsocks.conf.5 man
pages. Also, you can use -h, --help for all the possible options of the
torsocks script.

A configuration file named *torsocks.conf* is also provided for the user to
control some parameters.

More informations
--------------

torsocks is distributed under the GNU General Public License version 2.

Mailing list for help is <tor-talk@lists.torproject.org> and for development
use <tor-dev@lists.torproject.org>. You can find the project also on IRC server
irc.oftc.net (OFTC) in #tor and #tor-dev.

See more information about the Tor project at https://www.torproject.org.

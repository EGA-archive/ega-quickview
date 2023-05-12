# EGA-QuickView

EGA-QuickView is a FUSE file system to access EGA files remotely. It
works on Linux and [macOS 12](https://github.com/EGA-archive/ega-quickview-macos).

From the [libfuse description](https://github.com/libfuse/libfuse/blob/master/README.md):

> FUSE (Filesystem in Userspace) is an interface for userspace
> programs to export a filesystem to the Linux kernel. The FUSE
> project consists of two components: the fuse kernel module
> (maintained in the regular kernel repositories) and the libfuse
> userspace library [...]. libfuse provides
> the reference implementation for communicating with the FUSE kernel
> module.

EGA-QuickView is a combination of
[sshfs](https://github.com/libfuse/sshfs) and
[crypt4ghfs](https://github.com/EGA-archive/crypt4ghfs). That is, we
communicate with the EGA distribution servers over ssh, download files
(chunk by chunk) in Crypt4GH format and decrypt them transparently.

It is useful for a user to quickly browse through a file, without
downloading it entirely before being able to open it. It looses its
purpose if the user plans on scanning the entire file. For that
latter, it is more appropriate to download the files using the Aspera
solution, and decrypt the files locally with [Crypt4GH](https://crypt4gh.readthedocs.io).

## Installation

We need a few required packages (gcc, make, libsodium, libfuse, autoconf...)

    # On Debian-like systems
	apt install libfuse3-dev autoconf gcc make pkg-config libsodium-dev libssl-dev libglib2.0-dev

    # On others
	# TODO


You can then compile the EGA-qv code with:

	autoreconf -i
	./configure
	make

## Example

EGA-QuickView works over SSH and uses Crypt4GH. It therefore needs a Crypt4GH-compatible key.
2 arguments are required: the location of the EGA server and a mountpoint.
Credentials to connect to the EGA server can be passed similarly to a classic SSH connection.
The Crypt4GH key must be passed as a `-o` argument, in the options list.

	ega-qv [options] <EGA-server> <mountpoint>
	
For example, the user `silverdaz` can connect to `outbox.ega-archive.org`, using:

	ega-qv -o seckey=~/.ssh/c4gh.key silverdaz@outbox.ega-archive.org ~/EGA
	
You will get prompted for the Crypt4GH passphrase (and eventually your
password to connect to the server, unless you used an ssh-key
(recommended)).

## Todo

- [ ] Create documentation on ReadTheDocs
- [ ] Remove the passphrase prompt if the key is not locked (Not recommended).

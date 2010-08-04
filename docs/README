DESCRIPTION
	
	Rebind is a tool that implements the multiple A record DNS rebinding attack. Although this tool
	was originally written to target home routers, it can be used to target any public (non RFC1918) 
	IP address. 

	Rebind provides an external attacker access to a target router's internal Web interface. This 
	tool works on routers that implement the weak end system model in their IP stack, have specifically 
	configured firewall rules, and who bind their Web service to the router's WAN interface. Note that 
	remote administration does not need to be enabled for this attack to work. All that is required is 
	that a user inside the target network surf to a Web site that is controlled, or has been compromised, 
	by the attacker. See docs/whitepaper.pdf for a detailed description of the attack.

REQUIREMENTS
	
	In order to use Rebind, you must have a registered domain name. You must also register your
	attack machine as a nameserver for your domain; this can be done through your registrar. See 
	the docs/FAQ file for more information.

	Rebind is only supported on the Linux platform.

	Rebind must be run as root, and you must have iptables installed and listed in $PATH.

USAGE

	The only required command line options for Rebind are the -i and -d options. These specify the
	local interface name and your registered domain name respectively. Example:

		# ./rebind -i eth0 -d attacker.com

	Rebind provides a console shell for viewing and changing configuration settings. Type 'help'
	inside the console for a list of commands. For help with a particular command, type '<command> ?'.
	Most commands take no arguments and serve only to display status information. However, some commands 
	do provide the ability to add/edit configuration settings on the fly:

        	> config [key] [value]
                The config command can be used to display or edit the payload configuration, including the 
		default user name and password to use for basic authentication requests, the default path 
		to request during the rebinding process, the callback interval and a cookie value to be used 
		for the proxied requests. Note that because these are payload configuration values, they will 
		not take effect for existing active clients, as those clients have already recieved the payload.

        	> headers [add|del] [header] [value]
                The headers command can be used to display or edit specific HTTP header values that will be 
		appended to all HTTP requests sent through the Rebind HTTP proxy server. Note that although the 
		client-side JavaScript will attempt to send any HTTP headers that are specified, the XmlHttpRequest 
		object restricts certian headers, such as the Host header, from being sent. If a restricted header 
		is encountered, it will be skipped by the JavaScript code and will not be sent with the final request.

        	> save [file]
                The save command saves a copy of Rebind's current SQLite database. This database contains all 
		configuration information, logs, errors, requests and responses. By default it is saved to 'rebind.db' 
		in the current working directory. However, an alternate file name may be specified, such as 
		'save backup.db'. Note that Rebind's database is destroyed upon exit, so if you wish to save this 
		data, you must do so via the save command.

		> targets [add|del] [ip]
                The targets command can be used to display or edit explicit target IP addresses. If target IPs 
		are listed here, clients will be rebound to those IP addresses instead of the public IP address 
		of their gateway router. This is the same as the -t command line argument, except IP lists are 
		not supported; you must execute one 'targets' command for each IP address that you wish to add 
		to the list.

	To use the Rebind proxy, configure your browser settings to use <rebind ip>:664 as your HTTP proxy.

	To rebind client Web browsers, get them to browse to http://<your domain>/init.

KNOWN AFFECTED ROUTERS

	ActionTec MI-424WR
	ActionTec GT704-WG
	ActionTec GT701-WG
	Asus WL-520gU
	Belkin F5D7230-4 v.2000
	ClearAccess AG-10
	D-Link DIR-300
	D-Link DIR-320
	DD-WRT
	Dell TrueMobile 2300
	Linksys BEFSR41
	Linksys BEFW11S4
	Linksys WRT-160N
	Linksys WRT54G3G-ST
	Linksys WRT54Gv3
	Linksys WRT54GL
	OpenWRT
	PFSense
	Thomson ST585v6

TESTED BROWSERS

	Rebind has been successfully tested against the following browsers:
	
		IE6		Windows XP SP2
		IE7		Windows XP SP3
		IE8		Windows XP SP3
		IE8		Windows 7
		FF 3.0.15	Windows XP SP3
		FF 3.0.17	Ubuntu Linux 9.04
		FF 3.5.6	Ubuntu Linux 9.10
		FF 3.5.7	Windows XP SP3
		FF 3.6		Windows XP SP3
		FF 3.6		Windows 7
		FF 3.6		OSX 10.6.2
		Chrome 4.1	Windows XP SP3
		Opera 10.10	Windows XP SP3
		Opera 10.54	Windows XP SP3
		Safari 4.0.4	Windows XP SP3
		Safari 4.0.4	OSX 10.6.2

	Note that the above browsers are client browsers, i.e., the browser used by the victim. Only Firefox has been
	tested to work with Rebind's Web-based interface, and IE is known to not display the interface properly. So if 
	you are using Rebind, be sure to use Firefox or a similar browser.

INSTALLATION

	The ../bin/ directory contains statically compiled 32-bit and 64-bit Linux binaries. If you wish to compile 
	from source, run:

		$ make
		$ make install

	This will build Rebind and its dependencies and copy the resulting binary to the ../bin/ directory.

LICENSE

	The MIT License

	Copyright (c) 2010 Craig Heffner

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in
	all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
	THE SOFTWARE.

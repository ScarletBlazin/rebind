# Frequently Asked Questions #

1) How do I configure Rebind to handle DNS requests for my domain?

> Actually, you need to configure your domain to use Rebind as your primary DNS server. This is done
> in two steps: first, you need to register the machine that you intend to run Rebind from as a nameserver,
> then you must configure your domain to use that nameserver. Most registrars will let you perform both
> of these actions, although some don't and many make it difficult to find these settings, so you may
> have to search around a little.

> Go to the registrar where you registered your domain name (Host-Unlimited, GoDaddy, Yahoo, etc.)
> and first register two nameservers. You will want to register two because most registrars will require
> your domain to have at least two nameservers, and you want Rebind to handle all DNS lookups. Name the
> nameservers ns1 and ns2 and set their IP addresses to that of the machine from where you intend to run
> Rebind.

> Once you have registered your nameservers, go do your domain DNS settings and set these nameservers as
> the authoritative nameservers for your domain. If for example your domain is 'mydomain.com', you will
> enter ns1.mydomain.com and ns2.mydomain.com. Now all DNS traffic will be directed to the machine where
> you intend to run Rebind, which will allow Rebind to accept and handle all DNS requests for your domain.

2) What is the best registrar to use with Rebind?

> Typically any registrar should work, but you will need one that allows you to register nameservers and
> configure your domain's DNS settings. Most do, but some don't. Many make it difficult to register a nameserver.
> For example, DreamHost does not appear to allow clients to register their own nameservers. GoDaddy does, but
> the interface for doing so is hidden under several layers of ad-riddled pages.

> The easiest registar that I have found for creating custom DNS configurations as are needed by Rebind is
> Host-Unlimited (www.host-unlimited.com). Full disclosure: yes, I know the founder of HU. No, I don't make any
> money from HU. I just find them easy to use.

3) Where does Rebind store its log files?

> All data is logged to a SQLite database (/tmp/rebind.db). This database is deleted when Rebind exits (as well as
> when it starts), but if you wish to save a copy of it you can enter the 'save' command from the Rebind console
> interface. This will save a copy of the database to the current working directory under the name 'rebind.db' unless
> you specify an alternate name (i.e., 'save backup.db').

4) How can I prevent others from accessing Rebind's Web proxy?

> Configure your firewall to only allow your IP address to access TCP port 664. Although Rebind uses iptables itself,
> it will co-exist peacefully with other iptables rules in that it will not modify or remove any iptables entries
> that it did not create.

5) Does Rebind feature a whitelist/blacklist for targeting only specific IP addresses?

> No. Configure your firewall to only allow your target IP addresses to access the attack port (port 80 by default).
> Although Rebind uses iptables itself, it will co-exist peacefully with other iptables rules in that it will not
> modify or remove any iptables entries that it did not create.

6) Does Rebind run on Windows/Mac/BSD?

> No. Rebind has been built for and tested on Linux only, specifically, the Ubuntu distribution. It would likely not
> be difficult to port to BSD systems, but the firewall code will need to be changed to work with BSD's firewall as
> it currently only supports iptables.

> Windows? What's Windows? Seriously though, no. Porting to Windows would probably be more difficult than it's worth.
> But if you really want to port it to Windows, you're more than welcome to have a go at it.

7) I want to re-compile Rebind. What do I need?

> You'll need a standard C development environment (gcc, glibc, binutils, etc). Rebind also requires the sqlite3,
> termcap and readline libraries, but these are included with the Rebind source. If you have other versions of these
> libraries already installed on your system and wish to compile against them instead, edit the Makefile to exclude
> the local build directory when looking for include headers and libraries.

8) Does Rebind run on 64-bit systems?

> Yes.

9) Does Rebind support IPv6?

> No.

10) The attack page in Rebind is just a blank page. How do I add content to Rebind's default attack page?

> You don't. Well, you can (just edit the www/payload.html page in the source), but you will have to re-compile because
> all of the images and HTML/JS content are built in with the Rebind binary. Rebind was not built with the intention
> of making it pretty - it was built to attack things.

> The best way to deploy Rebind in a real-world scenario is to add a hidden iframe inside of another, more interesting
> page. Point the iframe src to the Rebind /init page.

11) How do I get people to browse to Rebind?

> If you need to ask that question, you probably shouldn't be using this tool. I'll give you a hint though: Google Wave.

12) I'm directing clients to the index page of Rebind's Web server, but they don't get any JavaScript back and it doesn't rebind my domain! What's wrong?

> There is no index page. You need to direct your clients to http://<your domain>/init.

13) Rebind displays the router's Basic Authentication prompt to the target user! What's going on?

> Rebind uses the JavaScript XMLHttpRequest in the client's browser to interact with the target router. While the
> XMLHttpRequest object does allow you to provide Basic Authentication credentials for the requests, if the credentials
> are wrong then the browser will prompt the user with the standard Basic Authentication login box. This is the default
> browser behavior. Further, when the initial DNS rebinding takes place, a Web request will be sent to the router;
> thus, you must supply Rebind with the credentials you wish to use before the client browses to your domain (the
> default is admin:admin). If you guess the credentials wrong, then they will get the pop-up prompt.

> However, there are ways to help mitigate this problem. Most routers will respond with a 404 error instead of a 401
> if you request a page that does not exist. By default Rebind makes a request for the router's index page during the
> DNS rebinding process, but this is configurable at runtime using the -r switch, or from the Rebind console using the
> 'config path' command. If you instead specify a page that you know will not exist on the router (such as '/foo.bar'),
> then the rebinding attack will execute successfully without a Basic Authentication prompt because the router will return
> a 404 page instead of a 401 response. Once you see the client appear in your list of active clients, you can request that
> same non-existent page ('/foo.bar' in this example) and examine the 404 headers and page content. If, for example, the
> 404 page looks like that of a Linksys router, and you know that Linksys routers use Basic Authentication, then you can
> decide if you want to attempt an exploit against the router, attempt to log in with default credentials and risk popping
> the authentication prompt in the client browser, or wait for another target to come along.

> Note that any Basic Authentication credentials that you send through Rebind's Web proxy will override Rebind's default
> Basic Authentication credentials.

14) When the target client is using a Firefox browser and the target router is an ActionTec MI424-WR, I keep getting '501 Not Implemented' errors when I try to log in. What's going on?

> The login is done via a POST request. The MI424-WR expects the Content-Type of the POST request to be 'application/x-www-form-urlencoded'.
> However, Firefox appends ';charset=utf-8' to all XMLHttpRequest Content-Type headers, making the actual header read
> 'application/x-www-form-urlencoded; charset=utf-8'. Although this is a valid HTTP header, the router is not expecting it and assumes
> that the wrong content type has been used.

> However, although the login and other form submissions for the the MI424-WR are performed via POST requests, they can also be done
> via GET requests. Since GET requests do not require a Content-Type header, using a GET request alleviates this issue. In order to
> make the process of converting POST requests into GET requests easier, a GreaseMonkey script is included with the Rebind release.
> You (the attacker) need to activate this GreaseMonkey script in your browser. Once it is activated, it will automatically convert
> all POST forms on the page to GET forms, allowing you to log in and re-configure router settings without the 501 error.

15) Why don't images display properly when using the Rebind HTTP proxy?

> Most router pages are fairly simple pages, but contain many images which increase bandwidth and load time. Additionally, the
> XmlHttpRequest object used by the client-side JavaScript is designed for retrieving text-based documents, not binary data. As such,
> Rebind filters out requests for files with common image file extensions (.jpg, .gif, .png, etc).

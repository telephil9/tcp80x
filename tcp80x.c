#include <u.h>
#include <libc.h>
#include <ctype.h>
#include <auth.h>
#include <bio.h>
#include <regexp.h>

typedef struct Pair Pair;

struct Pair
{
	Pair	*next;

	char	key[64];
	char	val[256];
	char	*att;
};

int trusted;

char remote[128];
char method[64];
char location[1024];

Pair *header;
int naheader;
Pair aheader[64];

char*
findrule(char *rulesfile, char *path)
{
	Biobuf *bio;
	char *s, *p, *d, *r;
	Reprog	*re;
	Resub m[16];

	if((bio = Bopen(rulesfile, OREAD)) == nil)
		sysfatal("open: %r");
	while(s = Brdstr(bio, '\n', 1)){
		p = s;
		while(strchr("\t ", *p))
			p++;
		d = nil;
		if(*p != '#'){
			if(d = strchr(p, '\t'))
				*d++ = 0;
			else if(d = strchr(p, ' '))
				*d++ = 0;
		}
		if(d == nil){
			free(s);
			continue;
		}
		while(strchr("\t ", *d))
			d++;

		if(re = regcomp(p)){
			memset(m, 0, sizeof(m));
			if(regexec(re, path, m, nelem(m))){
				r = malloc(1024);
				regsub(d, r, 1024, m, nelem(m));
				free(s);
				Bterm(bio);
				return r;
			}
		}
		free(s);
	}
	Bterm(bio);
	return nil;
}

void
dispatchrule(char *cmd)
{
	if(rfork(RFPROC|RFNOWAIT|RFFDG|RFREND) == 0){
		execl("/bin/rc", "rc", "-c", cmd, nil);
		exits("exec");
	}
	exits(nil);
}

Pair*
findhdr(Pair *h, char *key)
{
	if(h == nil)
		h = header;
	else
		h = h->next;
	for(; h; h = h->next)
		if(cistrcmp(h->key, key) == 0)
			break;
	return h;
}

char*
nstrcpy(char *d, char *s, int n)
{
	d[n-1] = 0;
	return strncpy(d, s, n-1);
}

char hex[] = "0123456789ABCDEF";

char*
urldec(char *d, char *s, int n)
{
	int c, x;
	char *r;

	r = d;
	x = 0;
	while(n > 1 && (c = *s++)){
		if(x){
			char *p;

			if((p = strchr(hex, toupper(c))) == nil)
				continue;
			*d <<= 4;
			*d |= p - hex;
			if(--x)
				continue;
		} else {
			if(c == '%'){
				x = 2;
				continue;
			}
			*d = c;
		}
		d++;
		n--;
	}
	*d = 0;
	return r;
}

char*
urlenc(char *d, char *s, int n)
{
	char *r;
	int c;

	r = d;
	while(n > 1 && (c = *s++)){
		if(isalnum(c) || strchr("$-_.+!*'(),", c) || strchr("/:;=@", c)){
			*d++ = c;
			n--;
		} else {
			if(n <= 3)
				break;
			*d++ = '%';
			*d++ = hex[(c>>4)&15];
			*d++ = hex[c&15];
			n -= 3;
		}
	}
	*d = 0;
	return r;
}

int
isleap(int year)
{
	return year%4==0 && (year%100!=0 || year%400==0);
}

long
hdate(char *s)
{
	int i;
	Tm tm;

	static int mday[2][12] = {
		31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
		31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
	};
	static char *wday[] = {
		"Sunday", "Monday", "Tuesday", "Wednesday",
		"Thursday", "Friday", "Saturday",
	};
	static char *mon[] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
	};

	/* Sunday, */
	for(i=0; i<nelem(wday); i++){
		if(cistrncmp(s, wday[i], strlen(wday[i])) == 0){
			s += strlen(wday[i]);
			break;
		}
		if(cistrncmp(s, wday[i], 3) == 0){
			s += 3;
			break;
		}
	}
	if(*s == ',')
		s++;
	if(*s == ' ')
		s++;
	/* 25- */
	if(!isdigit(s[0]) || !isdigit(s[1]) || (s[2]!='-' && s[2]!=' '))
		return -1;
	tm.mday = strtol(s, 0, 10);
	s += 3;
	/* Jan- */
	for(i=0; i<nelem(mon); i++)
		if(cistrncmp(s, mon[i], 3) == 0){
			tm.mon = i;
			s += 3;
			break;
		}
	if(i==nelem(mon))
		return -1;
	if(s[0] != '-' && s[0] != ' ')
		return -1;
	s++;
	/* 2002 */
	if(!isdigit(s[0]) || !isdigit(s[1]))
		return -1;
	tm.year = strtol(s, 0, 10);
	s += 2;
	if(isdigit(s[0]) && isdigit(s[1]))
		s += 2;
	else{
		if(tm.year <= 68)
			tm.year += 2000;
		else
			tm.year += 1900;
	}
	if(tm.mday==0 || tm.mday > mday[isleap(tm.year)][tm.mon])
		return -1;
	tm.year -= 1900;
	if(*s++ != ' ')
		return -1;
	if(!isdigit(s[0]) || !isdigit(s[1]) || s[2]!=':'
	|| !isdigit(s[3]) || !isdigit(s[4]) || s[5]!=':'
	|| !isdigit(s[6]) || !isdigit(s[7]) || s[8]!=' ')
		return -1;
	tm.hour = atoi(s);
	tm.min = atoi(s+3);
	tm.sec = atoi(s+6);
	if(tm.hour >= 24 || tm.min >= 60 || tm.sec >= 60)
		return -1;
	s += 9;
	if(cistrcmp(s, "GMT") != 0)
		return -1;
	nstrcpy(tm.zone, s, sizeof(tm.zone));
	tm.yday = 0;
	return tm2sec(&tm);
}

void
headers(char *path, Dir *d)
{
	char buf[1024], *f[6];
	int isdir;
	Tm *tm;

	if(tm = localtime(time(0))){
		nstrcpy(buf, asctime(tm), sizeof(buf));
		if(tokenize(buf, f, 6) == 6)
			print("Date: %s, %.2d %s %s %s %s\r\n",
				f[0], tm->mday, f[1], f[5], f[3], f[4]);
	}
	if(d && (tm = localtime(d->mtime))){
		nstrcpy(buf, asctime(tm), sizeof(buf));
		if(tokenize(buf, f, 6) == 6)
			print("Last-Modified: %s, %.2d %s %s %s %s\r\n",
				f[0], tm->mday, f[1], f[5], f[3], f[4]);
	}
	isdir = d && (d->qid.type & QTDIR);
	if(isdir || cistrstr(path, ".htm"))
		print("Content-Type: text/html; charset=utf-8\r\n");
	if(*path == '/')
		print("Content-Location: %s%s\r\n",
			urlenc(buf, path, sizeof(buf)), isdir ? "/" : "");
}

int
dircmp(Dir *a, Dir *b)
{
	return strcmp(a->name, b->name);
}

char*
fullurl(char *host, char *path, char *name, char *query)
{
	static char buf[1024];

	snprint(buf, sizeof(buf), "%s%s%s%s%s%s",
		host ? "http://" : "", host ? host : "", 
		path ? path : "/", name ? name : "",
		query ? "?" : "", query ? query : "");
	return buf;
}

void
respond(char *status)
{
	syslog(0, "tcp80x", "%s %s %s %s", remote, method, location, status);
	print("HTTP/1.1 %s\r\n", status);
}

int
dispatch(void)
{
	static char buf[8192], tmp[1024];
	char *p, *s, *status;
	int i, n, fd, badmeth, nobody, noindex, noslash;
	Pair *h;
	Dir *d;

	nobody = !cistrcmp(method, "HEAD");
	badmeth = !nobody && cistrcmp(method, "GET");
	if(badmeth){
		werrstr("%s method unsupported", method);
		status = "405 Method Not Allowed";
Error:
		if(!nobody)
			n = snprint(buf, sizeof(buf), 
			"<html><head><title>%s</title></head>\n"
			"<body><h1>%s</h1><pre>%r</pre></body></html>\n",
			status, status);
		else
			n = 0;
		respond(status);
		headers(".html", nil);
		print("Content-Length: %d\r\n\r\n%*s", n, n, buf);
		return -badmeth;
	}

	s = location;
	if(cistrncmp(s, "http:", 5) == 0)
		s += 5;
	else if(cistrncmp(s, "https:", 6) == 0)
		s += 6;
	if(s[0] == '/' && s[1] == '/')
		s = strchr(s+2, '/');
	if(s == nil || *s == 0)
		s = "/";
	nstrcpy(tmp, s, sizeof(tmp));
	if(s = strchr(tmp, '#'))
		*s = 0;
	noindex = 0;
	if(s = strchr(tmp, '?')){
		*s++ = 0;
		noindex = !cistrcmp(s, "noindex");
	}
	urldec(buf, tmp, sizeof(buf));

	noslash = 1;
	if(s = strrchr(buf, '/'))
		if(s[1] == 0)
			noslash = 0;

	cleanname(buf);
	if((fd = open(buf, OREAD)) < 0){
		rerrstr(buf, sizeof(buf));
		if(strstr(buf, "permission denied")){
			status = "403 Forbidden";
			goto Error;
		}
		status = "404 Not found";
		goto Error;
	}

	if((d = dirfstat(fd)) == nil){
		close(fd);
		status = "500 Internal Server Error";
		goto Error;
	}

	if(d->qid.type & QTDIR){
		int fd2;
		Dir *d2;

		if(noslash){
			status = "301 Moved Permanently";
			respond(status);
			headers(buf, d);

			h = findhdr(nil, "Host");
			p = strchr(location, '?');
			s = fullurl(h ? h->val : nil, urlenc(tmp, buf, sizeof(tmp)), "/", p ? p+1 : nil);
			if(!nobody)
				n = snprint(buf, sizeof(buf), 
				"<html><head><title>%s</title></head>\n"
				"<body><h1>%s</h1><pre>Moved to <a href=\"%s\">%s</a></pre></body></html>\n",
				status, status, s, s);
			else
				n = 0;
			print("Location: %s\r\nContent-Length: %d\r\n\r\n%*s", s, n, n, buf);
			goto Out;
		}

		if(!noindex){
			snprint(tmp, sizeof(tmp), "%s/index.html", buf);
			cleanname(tmp);
			if((fd2 = open(tmp, OREAD)) >= 0){
				if(d2 = dirfstat(fd2)){
					if((d2->qid.type & QTDIR) == 0){
						nstrcpy(buf, tmp, sizeof(buf));
						close(fd);
						fd = fd2;
						free(d);
						d = d2;
						goto Filecont;
					}
					free(d2);
				}
				close(fd2);
			}
		}

		respond("200 OK");
		headers(buf, d);
		print("\r\n");
		if(nobody)
			goto Out;

		print(	"<html><head><title>%s</title></head><body>"
			"<pre>\n<a href=\"/%s\">/</a>", 
			buf, noindex ? "?noindex" : "");
		for(p = buf+1; *p; p = s+1){
			if(s = strchr(p, '/'))
				*s = 0;
			print(	"<a href=\"%s/%s\">%s</a>/", 
				urlenc(tmp, buf, sizeof(tmp)), noindex ? "?noindex" : "", p);
			if(s == nil)
				break;
			*s = '/';
		}
		print("<hr>");

		free(d);
		d = nil;
		if((n = dirreadall(fd, &d)) > 0){
			qsort(d, n, sizeof d[0], (int (*)(void*, void*))dircmp);
			for(i=0; i<n; i++)
				print("<a href=\"%s%s\">%s</a>%s\n", 
					urlenc(tmp, d[i].name, sizeof(tmp)),
					(d[i].qid.type & QTDIR) ? (noindex ? "/?noindex" : "/") : "",
					d[i].name,
					(d[i].qid.type & QTDIR) ? "/" : "");
			free(d);
		}
		print("</pre></body></html>\n");
		return 1;
	} else {
		vlong start, end;

Filecont:
		h = findhdr(nil, "If-Modified-Since");
		if(h && !nobody){
			long t;

			if((t = hdate(h->val)) != -1){
				if(d->mtime <= t){
					respond("304 Not Modified");
					headers(buf, d);
					print("\r\n");
					goto Out;
				}
			}
		}

		h = findhdr(nil, "Range");
		while(h){
			if(findhdr(h, "Range"))
				break;
			if(s = strchr(h->val, '='))
				s++;
			else
				s = h->val;
			start = strtoll(s, &s, 10);
			if(*s++ != '-')
				break;
			if(*s == 0)
				end = d->length;
			else
				end = strtoll(s, &s, 10)+1;
			if(*s != 0 || (end <= start))
				break;
			respond("206 Partial content");
			print("Content-Range: bytes %lld-%lld/%lld\r\n",
				start, end-1, d->length);
			goto Content;
		}
		start = 0;
		end = d->length;
		respond("200 OK");
Content:
		headers(buf, d);
		if(end > start){
			print("Content-Length: %lld\r\n\r\n", end - start);
			if(nobody)
				goto Out;
			while(start < end){
				n = sizeof(buf);
				if((end - start) < n)
					n = end - start;
				if((n = pread(fd, buf, n, start)) <= 0)
					return -1;
				if(write(1, buf, n) != n)
					return -1;
				start += n;
			}
		} else {
			print("\r\n");
			if(nobody)
				goto Out;
			while((n = read(fd, buf, sizeof(buf))) > 0)
				if(write(1, buf, n) != n)
					return -1;
			return 1;
		}
	}
Out:
	close(fd);
	free(d);
	return 0;
}

char*
token(char *s, char *delim, char **pe)
{
	char *e;
	int d;

	d = 0;
	while(*s == ' ' || *s == '\t')
		s++;
	for(e = s; *e; e++){
		if(*e == '(')
			d++;
		if(d > 0){
			if(*e == ')')
				d--;
			s = e+1;
			continue;
		}
		if(strchr(delim, *e)){
			*e++ = 0;
			break;
		}
	}
	if(pe)
		*pe = e;
	while(s < e && *s == ' ' || *s == '\t')
		s++;
	while(--e >= s){
		if(*e != ' ' && *e != '\t')
			break;
		*e = 0;
	}
	return s;
}

int
parsequery(void)
{
	static char buf[1024], line[1024];
	char *p, *e, *k, *x, *s;
	int lineno, n;
	Pair *h;

	naheader = 0;
	lineno = 0;
	*line = 0;
	p = buf;
	e = buf + sizeof(buf);
	while((n = read(0, p, e - p)) > 0){
		p += n;
		while((p > buf) && (e = memchr(buf, '\n', p - buf))){
			if((e > buf) && (e[-1] == '\r'))
				e[-1] = 0;
			*e++ = 0;
			if(*buf != ' ' && *buf != '\t' && *line){
				if(lineno++ == 0){
					nstrcpy(method, token(line, "\t ", &s), sizeof(method));
					nstrcpy(location, token(s, "\t ", nil), sizeof(location));
				} else {
					if(lineno > 100)
						return -1;
					k = token(line, ":", &s);
					while(*s){
						if(naheader >= nelem(aheader))
							return -1;
						x = token(s, ",", &s);
						h = aheader + naheader++;
						nstrcpy(h->key, k, sizeof(h->key));
						nstrcpy(h->val, x, sizeof(h->val));
						if(x = strchr(h->val, ';')){
							*x++ = 0;
							x = token(x, ";", nil);
						}
						h->att = x;
						h->next = header;
						header = h;
					}
				}
			}
			nstrcpy(line, buf, sizeof(line));
			p -= e - buf;
			if(p > buf)
				memmove(buf, e, p - buf);
			if(*line == 0){
				if(method[0] == 0)
					return -1;
				return 0;
			}
		}
		e = buf + sizeof(buf);
	}
	return -1;
}

void
main(int argc, char **argv)
{
	static char buf[1024];
	char *r, *c;
	int n;

	r = nil;
	ARGBEGIN {
	case 'r':
		r = ARGF();
		break;
	case 't':
		trusted++;
		break;
	} ARGEND

	time(0);
	if(argc){
		int fd;
		snprint(buf, sizeof(buf), "%s/remote", argv[argc-1]);
		if((fd = open(buf, OREAD)) >= 0){
			if((n = read(fd, remote, sizeof(remote)-1)) >= 0){
				while(n > 0 && remote[n-1] == '\n')
					n--;
				remote[n] = 0;
			}
			close(fd);
		}
	}
	if(remote[0] == 0)
		strcpy(remote, "-");

	if(parsequery() < 0){
		respond("400 Bad Request");
		return;
	}

	if(r){
		c = findrule(r, location);
		if(c){
			if(cistrcmp(method, "GET") != 0){
				respond("405 Method Not Allowed");
				return;
			}
			dispatchrule(c);
			free(c);
			return;
		}
	}

	if(!trusted){
		if(addns("none", "/lib/namespace.httpd") < 0)
			return;
		if(bind("/usr/web", "/", MREPL) < 0)
			return;
		if(rfork(RFNOMNT) < 0)
			return;
	}
	dispatch();
	return;
}

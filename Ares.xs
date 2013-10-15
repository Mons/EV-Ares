#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"
#include "EVAPI.h"
//#include "evares.h"
#include "libevares.c"

static void callback_a(ev_ares_result_a * res) {
	dSP;
	struct ev_ares_a_reply* r = res->a;
	char ips[INET_ADDRSTRLEN];
	
	ENTER;
	SAVETMPS;
	
	PUSHMARK(SP);
	
	if (res->status != ARES_SUCCESS) {
		XPUSHs( &PL_sv_undef );
		XPUSHs( sv_2mortal( newSVpvf( "%s",res->error ) ) );
	} else {
		for (; r != NULL; r = r->next) {
			inet_ntop(AF_INET, &r->ip, ips, sizeof(ips));
			XPUSHs( sv_2mortal( newSVpvf( "%s", ips ) ) );
		}
	}
	
	PUTBACK;
	call_sv( (SV *) res->any, G_DISCARD | G_VOID );
	SvREFCNT_dec( (SV *) res->any );
	
	FREETMPS;
	LEAVE;
	return;
}

static void callback_aaaa(ev_ares_result_aaaa * res) {
	dSP;
	struct ev_ares_aaaa_reply* r = res->aaaa;
	char ips[INET6_ADDRSTRLEN];
	
	ENTER;
	SAVETMPS;
	
	PUSHMARK(SP);
	
	if (res->status != ARES_SUCCESS) {
		XPUSHs( &PL_sv_undef );
		XPUSHs( sv_2mortal( newSVpvf( "%s",res->error ) ) );
	} else {
		for (; r != NULL; r = r->next) {
			inet_ntop(AF_INET6, &r->ip6, ips, sizeof(ips));
			XPUSHs( sv_2mortal( newSVpvf( "%s", ips ) ) );
		}
	}
	
	PUTBACK;
	call_sv( (SV *) res->any, G_DISCARD | G_VOID );
	SvREFCNT_dec( (SV *) res->any );
	
	FREETMPS;
	LEAVE;
	return;
}

static void callback_ns(ev_ares_result_ns * res) {
	dSP;
	struct ev_ares_ns_reply* r = res->ns;
	
	ENTER;
	SAVETMPS;
	
	PUSHMARK(SP);
	
	if (res->status != ARES_SUCCESS) {
		XPUSHs( &PL_sv_undef );
		XPUSHs( sv_2mortal( newSVpvf( "%s",res->error ) ) );
	} else {
		for (; r != NULL; r = r->next) {
			XPUSHs( sv_2mortal( newSVpvf( "%s", r->host ) ) );
		}
	}
	
	PUTBACK;
	call_sv( (SV *) res->any, G_DISCARD | G_VOID );
	SvREFCNT_dec( (SV *) res->any );
	
	FREETMPS;
	LEAVE;
	return;
}

static void callback_mx(ev_ares_result_mx * res) {
	dSP;
	struct ev_ares_mx_reply* r = res->mx;
	
	ENTER;
	SAVETMPS;
	
	PUSHMARK(SP);
	
	if (res->status != ARES_SUCCESS) {
		XPUSHs( &PL_sv_undef );
		XPUSHs( sv_2mortal( newSVpvf( "%s",res->error ) ) );
	} else {
		for (; r != NULL; r = r->next) {
			XPUSHs( sv_2mortal( newSVpvf( "%s", r->host ) ) );
		}
	}
	
	PUTBACK;
	call_sv( (SV *) res->any, G_DISCARD | G_VOID );
	SvREFCNT_dec( (SV *) res->any );
	
	FREETMPS;
	LEAVE;
	return;
}

static void callback_txt(ev_ares_result_txt * res) {
	dSP;
	struct ev_ares_txt_reply* r = res->txt;
	
	ENTER;
	SAVETMPS;
	
	PUSHMARK(SP);
	
	if (res->status != ARES_SUCCESS) {
		XPUSHs( &PL_sv_undef );
		XPUSHs( sv_2mortal( newSVpvf( "%s",res->error ) ) );
	} else {
		for (; r != NULL; r = r->next) {
			XPUSHs( sv_2mortal( newSVpvf( "%s", r->txt ) ) );
		}
	}
	
	PUTBACK;
	call_sv( (SV *) res->any, G_DISCARD | G_VOID );
	SvREFCNT_dec( (SV *) res->any );
	
	FREETMPS;
	LEAVE;
	return;
}

static void callback_srv(ev_ares_result_srv * res) {
	dSP;
	struct ev_ares_srv_reply* r = res->srv;
	
	ENTER;
	SAVETMPS;
	
	PUSHMARK(SP);
	
	if (res->status != ARES_SUCCESS) {
		XPUSHs( &PL_sv_undef );
		XPUSHs( sv_2mortal( newSVpvf( "%s",res->error ) ) );
	} else {
		for (; r != NULL; r = r->next) {
			AV *res = newAV();
			av_push(res, newSVuv( r->priority ));
			av_push(res, newSVuv( r->weight ));
			av_push(res, newSVuv( r->port ));
			av_push(res, newSVpvf( "%s",r->host ));
			XPUSHs( sv_2mortal( newRV_noinc((SV *)res) ) );
		}
	}
	
	PUTBACK;
	call_sv( (SV *) res->any, G_DISCARD | G_VOID );
	SvREFCNT_dec( (SV *) res->any );
	
	FREETMPS;
	LEAVE;
	return;
}

typedef struct {
	int  cv;
	int  count;
	AV * res;
	SV * query;
	SV * cb;
} ev_ares_any;

#define check_any() STMT_START {\
	if (any->cv == 0) {\
		dSP;\
		ENTER;\
		SAVETMPS;\
		PUSHMARK(SP);\
		EXTEND(SP,av_len(any->res)+1);\
		PUSHs(sv_2mortal(newRV_noinc( (SV *) any->res )));\
		PUTBACK;\
		call_sv( any->cb, G_DISCARD | G_VOID );\
		SvREFCNT_dec( any->cb );\
		SvREFCNT_dec( any->query );\
		SvREFCNT_dec((SV *) res->any);\
		FREETMPS;\
		LEAVE;\
	}\
} STMT_END

static void callback_any_soa(ev_ares_result_soa * res) {
	struct ev_ares_soa_reply* r = res->soa;
	ev_ares_any *any = (ev_ares_any *) SvPVX((SV *) res->any);
	any->cv--;
	if (res->status == ARES_SUCCESS) {
		any->count++;
		AV * one = newAV();av_extend(one, 11);
		av_push(one, newSVsv(any->query));
		av_push(one, newSVpvs("soa"));
		av_push(one, newSVpvs("in"));
		av_push(one, newSVuv(r->ttl));
		av_push(one, newSVpvf("%s",r->nsname));
		av_push(one, newSVpvf("%s",r->hostmaster));
		av_push(one, newSVuv(r->serial));
		av_push(one, newSVuv(r->refresh));
		av_push(one, newSVuv(r->retry));
		av_push(one, newSVuv(r->expire));
		av_push(one, newSVuv(r->minttl));
		av_push(any->res,newRV_noinc((SV*)one));
	}
	check_any();
	return;
}

static void callback_any_a(ev_ares_result_a * res) {
	struct ev_ares_a_reply* r = res->a;
	ev_ares_any *any = (ev_ares_any *) SvPVX((SV *) res->any);
	char ips[INET_ADDRSTRLEN];
	any->cv--;
	if (res->status == ARES_SUCCESS) {
		for (; r != NULL; r = r->next) {
			inet_ntop(AF_INET, &r->ip, ips, sizeof(ips));
			any->count++;
			AV * one = newAV();av_extend(one, 5);
			av_push(one, newSVsv(any->query));
			av_push(one, newSVpvs("a"));
			av_push(one, newSVpvs("in"));
			av_push(one, newSVuv(r->ttl));
			av_push(one, newSVpvf( "%s", ips ));
			av_push(any->res,newRV_noinc((SV*)one));
		}
	}
	check_any();
	return;
}

static void callback_any_aaaa(ev_ares_result_aaaa * res) {
	struct ev_ares_aaaa_reply* r = res->aaaa;
	ev_ares_any *any = (ev_ares_any *) SvPVX((SV *) res->any);
	char ips[INET6_ADDRSTRLEN];
	any->cv--;
	if (res->status == ARES_SUCCESS) {
		for (; r != NULL; r = r->next) {
			inet_ntop(AF_INET6, &r->ip6, ips, sizeof(ips));
			any->count++;
			AV * one = newAV();av_extend(one, 5);
			av_push(one, newSVsv(any->query));
			av_push(one, newSVpvs("aaaa"));
			av_push(one, newSVpvs("in"));
			av_push(one, newSVuv(r->ttl));
			av_push(one, newSVpvf( "%s", ips ));
			av_push(any->res,newRV_noinc((SV*)one));
		}
	}
	check_any();
	return;
}

static void callback_any_mx(ev_ares_result_mx * res) {
	struct ev_ares_mx_reply* r = res->mx;
	ev_ares_any *any = (ev_ares_any *) SvPVX((SV *) res->any);
	any->cv--;
	if (res->status == ARES_SUCCESS) {
		for (; r != NULL; r = r->next) {
			any->count++;
			AV * one = newAV();av_extend(one, 6);
			av_push(one, newSVsv(any->query));
			av_push(one, newSVpvs("mx"));
			av_push(one, newSVpvs("in"));
			av_push(one, newSVuv(r->ttl));
			av_push(one, newSVuv(r->priority));
			av_push(one, newSVpvf("%s",r->host));
			av_push(any->res,newRV_noinc((SV*)one));
		}
	}
	check_any();
	return;
}

static void callback_any_ns(ev_ares_result_ns * res) {
	struct ev_ares_ns_reply* r = res->ns;
	ev_ares_any *any = (ev_ares_any *) SvPVX((SV *) res->any);
	any->cv--;
	if (res->status == ARES_SUCCESS) {
		for (; r != NULL; r = r->next) {
			any->count++;
			AV * one = newAV();av_extend(one, 5);
			av_push(one, newSVsv(any->query));
			av_push(one, newSVpvs("ns"));
			av_push(one, newSVpvs("in"));
			av_push(one, newSVuv(r->ttl));
			av_push(one, newSVpvf("%s",r->host));
			av_push(any->res,newRV_noinc((SV*)one));
		}
	}
	check_any();
	return;
}

static void callback_any_txt(ev_ares_result_txt * res) {
	struct ev_ares_txt_reply* r = res->txt;
	ev_ares_any *any = (ev_ares_any *) SvPVX((SV *) res->any);
	any->cv--;
	if (res->status == ARES_SUCCESS) {
		for (; r != NULL; r = r->next) {
			any->count++;
			AV * one = newAV();av_extend(one, 5);
			av_push(one, newSVsv(any->query));
			av_push(one, newSVpvs("txt"));
			av_push(one, newSVpvs("in"));
			av_push(one, newSVuv(r->ttl));
			av_push(one, newSVpvf("%s",r->txt));
			av_push(any->res,newRV_noinc((SV*)one));
		}
	}
	check_any();
	return;
}

static void callback_any_srv(ev_ares_result_srv * res) {
	struct ev_ares_srv_reply* r = res->srv;
	ev_ares_any *any = (ev_ares_any *) SvPVX((SV *) res->any);
	any->cv--;
	if (res->status == ARES_SUCCESS) {
		for (; r != NULL; r = r->next) {
			any->count++;
			AV * one = newAV();av_extend(one, 8);
			av_push(one, newSVsv(any->query));
			av_push(one, newSVpvs("ns"));
			av_push(one, newSVpvs("in"));
			av_push(one, newSVuv(r->ttl));
			av_push(one, newSVuv( r->priority ));
			av_push(one, newSVuv( r->weight ));
			av_push(one, newSVuv( r->port ));
			av_push(one, newSVpvf( "%s",r->host ));
			av_push(any->res,newRV_noinc((SV*)one));
		}
	}
	check_any();
	return;
}

static void callback_any_ptr(ev_ares_result_ptr * res) {
	struct ev_ares_ptr_reply* r = res->ptr;
	ev_ares_any *any = (ev_ares_any *) SvPVX((SV *) res->any);
	any->cv--;
	if (res->status == ARES_SUCCESS) {
		for (; r != NULL; r = r->next) {
			any->count++;
			AV * one = newAV();av_extend(one, 5);
			av_push(one, newSVsv(any->query));
			av_push(one, newSVpvs("ptr"));
			av_push(one, newSVpvs("in"));
			av_push(one, newSVuv(r->ttl));
			av_push(one, newSVpvf("%s",r->host));
			av_push(any->res,newRV_noinc((SV*)one));
		}
	}
	check_any();
	return;
}

static ev_ares resolver;

#define RES_SOA   0b0000000000000001
#define RES_NS    0b0000000000000010
#define RES_A     0b0000000000000100
#define RES_AAAA  0b0000000000001000
#define RES_MX    0b0000000000010000
#define RES_SRV   0b0000000000100000
#define RES_TXT   0b0000000001000000
#define RES_PTR   0b0000000010000000
#define RES_NAPTR 0b0000000100000000
#define RES_ALL   0b0000000111111111

MODULE = EV::Ares		PACKAGE = EV::Ares

BOOT:
{
	I_EV_API ("EV::Ares");
	int status;
	if ((status = ares_library_init(ARES_LIB_INIT_ALL) )!= ARES_SUCCESS) {
		croak("Ares error: %s",ares_strerror(status));
	}
	
	if (( status = ev_ares_init(&resolver, 1) ) != ARES_SUCCESS) {
		croak("Ares error: %s\n",ares_strerror(status));
	}
}

void any(SV *host, SV *cb)
	PROTOTYPE: $&
	PPCODE:
		SV *rr = newSV(sizeof(ev_ares_any));
		SvUPGRADE(rr,SVt_PV);
		ev_ares_any * any = (ev_ares_any *) SvPVX(rr);
		any->cv = 0;
		any->cb = SvREFCNT_inc(cb);
		any->query = SvREFCNT_inc(host);
		any->res = newAV();
		any->count = 0;
		
		any->cv++;
		ev_ares_soa(EV_DEFAULT,&resolver,SvPV_nolen(host),rr,callback_any_soa);
		any->cv++;
		ev_ares_ns(EV_DEFAULT,&resolver,SvPV_nolen(host),rr,callback_any_ns);
		any->cv++;
		ev_ares_a(EV_DEFAULT,&resolver,SvPV_nolen(host),rr,callback_any_a);
		any->cv++;
		ev_ares_aaaa(EV_DEFAULT,&resolver,SvPV_nolen(host),rr,callback_any_aaaa);
		any->cv++;
		ev_ares_mx(EV_DEFAULT,&resolver,SvPV_nolen(host),rr,callback_any_mx);
		any->cv++;
		ev_ares_txt(EV_DEFAULT,&resolver,SvPV_nolen(host),rr,callback_any_txt);

void resolve(SV *cls, SV *host, SV * type, ...)
	PROTOTYPE: $$@&
	PPCODE:
		SV * cb = ST(items-1);
		STRLEN l;
		char * t = SvPV( type,l );
		if (l < 1) croak("Bad type: %s",t);
		if (items > 4) {
			warn("extra items");
			//opt = newHV();
			int i;
			for (i = 3; i < items-1; i+= 2) {
				// accept => AV(type[])
				//if (strcmp(SvPV_nolen(ST(i))))
				warn("%s = %s", SvPV_nolen(ST(i)), SvPV_nolen(ST(i+1)));
			}
		}
		int flags = 0;
		if (l == 1 ) {
			if (*t == '*') {
				flags |= RES_ALL;
			}
			else
			if (strncasecmp( t,"a",1 )) {
				flags |= RES_A;
			}
			else {
				croak("Bad type: %s",t);
			}
		}
		else
		if (l == 2) {
			if (strncasecmp( t,"ns",2 )) {
				flags |= RES_NS;
			}
			else
			if (strncasecmp( t,"mx",2 )) {
				flags |= RES_MX;
			}
			else {
				croak("Bad type: %s",t);
			}
		}
		else
		if (l == 3) {
			if (strncasecmp( t,"soa",3 ) == 0) {
				flags |= RES_SOA;
			}
			else
			if (strncasecmp( t,"txt",3 ) == 0) {
				flags |= RES_TXT;
			}
			else
			if (strncasecmp( t,"ptr",3 ) == 0) {
				flags |= RES_PTR;
			}
			else
			if (strncasecmp( t,"srv",3 ) == 0) {
				flags |= RES_SRV;
			}
			else {
				croak("Bad type: %s",t);
			}
		}
		else
		if (l == 4 && strncasecmp( t,"aaaa",4 ) == 0) {
			flags |= RES_AAAA;
		}
		else
		if (l == 5 && strncasecmp( t,"naptr",5 ) == 0) {
			flags |= RES_NAPTR;
		}
		else {
			croak("Bad type: %s",t);
		}
		
		SV *rr = newSV(sizeof(ev_ares_any));
		SvUPGRADE(rr,SVt_PV);
		ev_ares_any * any = (ev_ares_any *) SvPVX(rr);
		any->cv = 0;
		any->cb = SvREFCNT_inc(cb);
		any->query = SvREFCNT_inc(host);
		any->res = newAV();
		any->count = 0;
		
		if (flags & RES_SOA) {
			any->cv++;
			ev_ares_soa(EV_DEFAULT,&resolver,SvPV_nolen(host),rr,callback_any_soa);
		}
		if (flags & RES_NS) {
			any->cv++;
			ev_ares_ns(EV_DEFAULT,&resolver,SvPV_nolen(host),rr,callback_any_ns);
		}
		if (flags & RES_A) {
			any->cv++;
			ev_ares_a(EV_DEFAULT,&resolver,SvPV_nolen(host),rr,callback_any_a);
		}
		if (flags & RES_AAAA) {
			any->cv++;
			ev_ares_aaaa(EV_DEFAULT,&resolver,SvPV_nolen(host),rr,callback_any_aaaa);
		}
		if (flags & RES_MX) {
			any->cv++;
			ev_ares_mx(EV_DEFAULT,&resolver,SvPV_nolen(host),rr,callback_any_mx);
		}
		if (flags & RES_TXT) {
			any->cv++;
			ev_ares_txt(EV_DEFAULT,&resolver,SvPV_nolen(host),rr,callback_any_txt);
		}
		if (flags & RES_TXT) {
			any->cv++;
			ev_ares_ptr(EV_DEFAULT,&resolver,SvPV_nolen(host),rr,callback_any_ptr);
		}

void a(char *host, SV *cb)
	PROTOTYPE: $&
	PPCODE:
		ev_ares_a(EV_DEFAULT,&resolver,host,SvREFCNT_inc(cb),callback_a);

void aaaa(char *host, SV *cb)
	PROTOTYPE: $&
	PPCODE:
		ev_ares_aaaa(EV_DEFAULT,&resolver,host,SvREFCNT_inc(cb),callback_aaaa);

void ns(char *host, SV *cb)
	PROTOTYPE: $&
	PPCODE:
		ev_ares_ns(EV_DEFAULT,&resolver,host,SvREFCNT_inc(cb),callback_ns);

void mx(char *host, SV *cb)
	PROTOTYPE: $&
	PPCODE:
		ev_ares_mx(EV_DEFAULT,&resolver,host,SvREFCNT_inc(cb),callback_mx);

void txt(char *host, SV *cb)
	PROTOTYPE: $&
	PPCODE:
		ev_ares_txt(EV_DEFAULT,&resolver,host,SvREFCNT_inc(cb),callback_txt);

void srv(char *type, char *proto, char *host, SV *cb)
	PROTOTYPE: $$$&
	PPCODE:
		SV *rr = sv_2mortal(newSVpvf("_%s._%s.%s",type,proto,host));
		warn("Resolve %s",SvPVX(rr));
		ev_ares_srv(EV_DEFAULT,&resolver,SvPVX(rr),SvREFCNT_inc(cb),callback_srv);

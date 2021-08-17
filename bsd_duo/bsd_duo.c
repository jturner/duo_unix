/*-
 * Copyright (c) 2019 James Turner <jaturner@duo.com>
 * Copyright (c) 2001 Hans Insulander <hin@openbsd.org>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "common.h"
#include "util.h"
#include "duo.h"

#define DUO_CONF        DUO_CONF_DIR "/bsd_duo.conf"

struct login_ctx {
    const char  *config;
    const char  *duouser;
    const char  *host;
    uid_t        uid;
};

static int
__ini_handler(void *u, const char *section, const char *name, const char *val)
{
    struct duo_config *cfg = (struct duo_config *)u;
    if (!duo_common_ini_handler(cfg, section, name, val)) {
        fprintf(stderr, "Invalid bsd_duo option: '%s'\n", name);
        return (0);
    }
    return (1);
}

static int
do_auth(struct login_ctx *ctx)
{
    struct duo_config cfg;
    struct passwd *pw;
    duo_t *duo;
    duo_code_t code;
    const char *config, *p, *duouser;
    const char *host = NULL;
    int i, flags, ret, prompts, matched;

    if ((pw = getpwnam(ctx->duouser)) == NULL) {
        fprintf(stderr, "Who are you?");
	return (AUTH_FAILED);
    }

    duouser = ctx->duouser ? ctx->duouser : pw->pw_name;
    config = ctx->config ? ctx->config : DUO_CONF;
    flags = 0;

    duo_config_default(&cfg);

    /* Load our private config. */
    if ((i = duo_parse_config(config, __ini_handler, &cfg)) != 0 ||
            (!cfg.apihost || !cfg.apihost[0] || !cfg.skey || !cfg.skey[0] ||
                !cfg.ikey || !cfg.ikey[0])) {
        switch (i) {
        case -2:
            fprintf(stderr, "%s must be readable only by "
                "user '%s'\n", config, pw->pw_name);
            break;
        case -1:
            fprintf(stderr, "Couldn't open %s: %s\n",
                config, strerror(errno));
            break;
        case 0:
            fprintf(stderr, "Missing host, ikey, or skey in %s\n",
                config);
            break;
        default:
            fprintf(stderr, "Parse error in %s, line %d\n",
                config, i);
            break;
        }
        /* Implicit "safe" failmode for local configuration errors */
        if (cfg.failmode == DUO_FAIL_SAFE) {
            return (AUTH_OK);
        }
        return (AUTH_FAILED);
    }


#ifdef OPENSSL_FIPS
    /*
     * When fips_mode is configured, invoke OpenSSL's FIPS_mode_set() API. Note
     * that in some environments, FIPS may be enabled system-wide, causing FIPS
     * operation to be enabled automatically when OpenSSL is initialized.  The
     * fips_mode option is an experimental feature allowing explicit entry to FIPS
     * operation in cases where it isn't enabled globally at the OS level (for
     * example, when integrating directly with the OpenSSL FIPS Object Module).
     */
    if(!FIPS_mode_set(cfg.fips_mode)) {
        /* The smallest size buff can be according to the openssl docs */
        char buff[256];
        int error = ERR_get_error();
        ERR_error_string_n(error, buff, sizeof(buff));
        duo_syslog(LOG_ERR, "Unable to start fips_mode: %s", buff);

       return (AUTH_FAILED);
    }
#else
    if(cfg.fips_mode) {
        duo_syslog(LOG_ERR, "FIPS mode flag specified, but OpenSSL not built with FIPS support. Failing the auth.");
        return (AUTH_FAILED);
    }
#endif

    prompts = cfg.prompts;
    /* Check group membership. */
    matched = duo_check_groups(pw, cfg.groups, cfg.groups_cnt);
    if (matched == -1) {
        close_config(&cfg);
        return (AUTH_FAILED);
    } else if (matched == 0) {
        duo_syslog(LOG_INFO, "User %s bypassed Duo 2FA due to user's UNIX group", duouser);
        close_config(&cfg);
        return (AUTH_FAILED);
    }

    /* Use GECOS field if called for */
    if ((cfg.send_gecos || cfg.gecos_username_pos >= 0) && !ctx->duouser) {
        if (strlen(pw->pw_gecos) > 0) {
            if (cfg.gecos_username_pos >= 0) {
                duouser = duo_split_at(pw->pw_gecos, cfg.gecos_delim, cfg.gecos_username_pos);
                if (duouser == NULL || (strcmp(duouser, "") == 0)) {
                    duo_log(LOG_DEBUG, "Could not parse GECOS field", pw->pw_name, NULL, NULL);
                    duouser = pw->pw_name;
                }
            } else {
                duouser = pw->pw_gecos;
            }
        } else {
            duo_log(LOG_WARNING, "Empty GECOS field", pw->pw_name, NULL, NULL);
        }
    }

    /* Try Duo auth. */
    if ((duo = duo_open(cfg.apihost, cfg.ikey, cfg.skey,
                    "bsd_duo/" PACKAGE_VERSION,
                    cfg.noverify ? "" : cfg.cafile,
                    cfg.https_timeout, cfg.http_proxy)) == NULL) {
        duo_log(LOG_ERR, "Couldn't open Duo API handle",
            pw->pw_name, host, NULL);
        close_config(&cfg);
        return (AUTH_FAILED);
    }

    if (cfg.accept_env) {
        flags |= DUO_FLAG_ENV;
    }

    ret = AUTH_FAILED;

    for (i = 0; i < prompts; i++) {
        code = duo_login(duo, duouser, host, flags,
                    NULL, cfg.failmode);
        if (code == DUO_FAIL) {
            duo_log(LOG_WARNING, "Failed Duo login",
                duouser, host, duo_geterr(duo));
            if ((flags & DUO_FLAG_SYNC) == 0) {
                printf("\n");
            }
            /* The autopush failed, fall back to regular process */
            if (cfg.autopush && i == 0) {
                flags = 0;
                duo_reset_conv_funcs(duo);
            }
            /* Keep going */
            continue;
        }
        /* Terminal conditions */
        if (code == DUO_OK) {
            if ((p = duo_geterr(duo)) != NULL) {
                duo_log(LOG_WARNING, "Skipped Duo login",
                    duouser, host, p);
            } else {
                duo_log(LOG_INFO, "Successful Duo login",
                    duouser, host, NULL);
            }
            ret = AUTH_OK;
        } else if (code == DUO_ABORT) {
            duo_log(LOG_WARNING, "Aborted Duo login",
                duouser, host, duo_geterr(duo));
        } else if (code == DUO_FAIL_SAFE_ALLOW) {
            duo_log(LOG_WARNING, "Failsafe Duo login",
                duouser, host, duo_geterr(duo));
                        ret = AUTH_OK;
        } else if (code == DUO_FAIL_SECURE_DENY) {
            duo_log(LOG_WARNING, "Failsecure Duo login",
                duouser, host, duo_geterr(duo));
        } else {
            duo_log(LOG_ERR, "Error in Duo login",
                duouser, host, duo_geterr(duo));
        }
        break;
    }
    duo_close(duo);
    close_config(&cfg);

    return (ret);
}

int
pwd_login(char *username, char *password, char *wheel, int lastchance,
    char *class, struct passwd *pwd)
{
	struct login_ctx ctx[1];
	size_t plen;
	char *goodhash = NULL;
	int passok = 0;

	memset(ctx, 0, sizeof(ctx));
	ctx->duouser = username;

	if (wheel != NULL && strcmp(wheel, "yes") != 0) {
		fprintf(back, BI_VALUE " errormsg %s\n",
		    auth_mkvalue("you are not in group wheel"));
		fprintf(back, BI_REJECT "\n");
		return (AUTH_FAILED);
	}
	if (password == NULL)
		return (AUTH_FAILED);

	if (pwd)
		goodhash = pwd->pw_passwd;

	setpriority(PRIO_PROCESS, 0, -4);

	if (crypt_checkpass(password, goodhash) == 0)
		passok = 1;
	plen = strlen(password);
	explicit_bzero(password, plen);

	if (!passok)
		return (AUTH_FAILED);

	if (login_check_expire(back, pwd, class, lastchance) == 0)
		fprintf(back, BI_AUTH "\n");
	else
		return (AUTH_FAILED);

	return do_auth(ctx);
}

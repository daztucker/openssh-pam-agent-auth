/* $OpenBSD$ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2008 Damien Miller.  All rights reserved.
 * Copyright (c) 2008 Jamie Beverly.
 * Copyright (c) 2022 Tobias Heider <tobias.heider@canonical.com>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "../../config.h"
#include <syslog.h>

#include <security/pam_appl.h>
#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "hostfile.h"
#include "auth.h"
#include "authfd.h"
#include "authfile.h"
#include "auth-options.h"
#include "crypto_api.h"
#include "digest.h"
#include "log.h"
#include "misc.h"
#include "sshbuf.h"
#include "sshkey.h"

#define CHALLENGE_LEN	32
#define UNUSED(expr) do { (void)(expr); } while (0)

const char	*authorized_keys_file = "/etc/security/authorized_keys";

extern char	*__progname;

static FILE *
pam_openfile(const char *file, struct passwd *pw)
{
	char line[1024];
	struct stat st;
	int fd;
	FILE *f;

	if ((fd = open(file, O_RDONLY|O_NONBLOCK)) == -1) {
		if (errno != ENOENT)
			debug("Could not open authorized_keys '%s': %s", file,
			    strerror(errno));
		return NULL;
	}

	if (fstat(fd, &st) == -1) {
		close(fd);
		return NULL;
	}
	if (!S_ISREG(st.st_mode)) {
		logit("User %s authorized_keys %s is not a regular file",
		    pw->pw_name, file);
		close(fd);
		return NULL;
	}
	unset_nonblock(fd);
	if ((f = fdopen(fd, "r")) == NULL) {
		close(fd);
		return NULL;
	}
	if (safe_path_fd(fileno(f), file, pw, line, sizeof(line)) != 0) {
		fclose(f);
		logit("Authentication refused: %s", line);
		return NULL;
	}

	return f;
}

/* obtain a list of keys from the agent */
static int
pam_get_agent_identities(int *agent_fdp,
    struct ssh_identitylist **idlistp)
{
	int r, agent_fd;
	struct ssh_identitylist *idlist;

	if ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		if (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		return r;
	}
	if ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		debug_fr(r, "ssh_fetch_identitylist");
		close(agent_fd);
		return r;
	}
	/* success */
	*agent_fdp = agent_fd;
	*idlistp = idlist;
	debug_f("agent returned %zu keys", idlist->nkeys);
	return 0;
}

/*
 * Check a single line of an authorized_keys-format file. Returns 0 if key
 * matches, -1 otherwise. Will return key/cert options via *authoptsp
 * on success. "loc" is used as file/line location in log messages.
 */
static int
pam_check_authkey_line(pam_handle_t *pamh, struct passwd *pw, struct sshkey *key,
    char *cp, const char *loc)
{
	int want_keytype = key->type;
	struct sshkey *found = NULL;
	struct sshauthopt *keyopts = NULL, *finalopts = NULL;
	char *key_options = NULL, *fp = NULL;
	const char *reason = NULL;
	int ret = -1;

	if (sshkey_is_cert(key))
		goto out;

	if ((found = sshkey_new(want_keytype)) == NULL) {
		debug3_f("keytype %d failed", want_keytype);
		goto out;
	}

	/* XXX djm: peek at key type in line and skip if unwanted */

	if (sshkey_read(found, &cp) != 0) {
		/* no key?  check for options */
		debug2("%s: check options: '%s'", loc, cp);
		key_options = cp;
		if (sshkey_advance_past_options(&cp) != 0) {
			reason = "invalid key option string";
			goto fail_reason;
		}
		skip_space(&cp);
		if (sshkey_read(found, &cp) != 0) {
			/* still no key?  advance to next line*/
			debug2("%s: advance: '%s'", loc, cp);
			goto out;
		}
	}
	/* Parse key options now; we need to know if this is a CA key */
	if ((keyopts = sshauthopt_parse(key_options, &reason)) == NULL) {
		debug("%s: bad key options: %s", loc, reason);
		goto out;
	}
	/* Plain key: check it against key found in file */
	if (!sshkey_equal(found, key) || keyopts->cert_authority)
		goto out;

	/* We have a candidate key, perform authorisation checks */
	if ((fp = sshkey_fingerprint(found, SSH_DIGEST_SHA256,
	    SSH_FP_DEFAULT)) == NULL)
		fatal_f("fingerprint failed");

	pam_syslog(pamh, LOG_INFO, "%s: matching %s found: %s %s", loc,
	    sshkey_is_cert(key) ? "CA" : "key", sshkey_type(found), fp);

	/* That's all we need for plain keys. */
	verbose("Accepted key %s %s found at %s",
	    sshkey_type(found), fp, loc);
	finalopts = keyopts;
	keyopts = NULL;

	/* success */
	ret = 0;
	goto out;

 fail_reason:
	error("%s", reason);
 out:
	free(fp);
	sshauthopt_free(keyopts);
	sshauthopt_free(finalopts);
	sshkey_free(found);
	return ret;
}

static int
pam_user_key_allowed(pam_handle_t *pamh, const char *ruser, struct sshkey *key,
    char *file)
{
	struct passwd *pw = getpwuid(0);
	char *cp, *line = NULL, loc[256];
	FILE *f;
	size_t linesize = 0;
	int found_key = 0;
	u_long linenum = 0, nonblank = 0;

	f = pam_openfile(file, pw);
	if (f == NULL)
		return 0;

	while (getline(&line, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire file */
		if (found_key)
			continue;

		/* Skip leading whitespace, empty and comment lines. */
		cp = line;
		skip_space(&cp);
		if (!*cp || *cp == '\n' || *cp == '#')
			continue;

		nonblank++;
		snprintf(loc, sizeof(loc), "%.200s:%lu", file, linenum);
		if (pam_check_authkey_line(pamh, pw, key, cp, loc) == 0)
			found_key = 1;
	}
	free(line);
	return found_key;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	u_char p[CHALLENGE_LEN];
	struct ssh_identitylist *idlist = NULL;
	const char *user;
	const char *ruser;
	int ret = PAM_AUTH_ERR, agent_fd = -1;
	size_t j;

	pam_get_item(pamh, PAM_USER, (void *) &user);
	pam_get_item(pamh, PAM_RUSER, (void *) &ruser);
	if (ruser == NULL)
		ruser = getpwuid(getuid())->pw_name;

	if (getpwnam(user) == NULL || getpwnam(ruser) == NULL) {
		pam_syslog(pamh, LOG_CRIT, "getpwname() failed.");
		goto exit;
	}

	if (pam_get_agent_identities(&agent_fd, &idlist) != 0) {
		pam_syslog(pamh, LOG_CRIT, "pam_get_agent_identities() failed.");
		goto exit;
	}

	for (j = 0; j < idlist->nkeys; j++) {
		/* Check if key in authorized_keys */
		if (!pam_user_key_allowed(pamh, ruser, idlist->keys[j],
		    authorized_keys_file))
			continue;

		/* Generate random challenge */
		randombytes(p, CHALLENGE_LEN);

		/* Sign challenge via ssh-agent */
		u_char *sig = NULL;
		size_t	slen = 0;
		if (ssh_agent_sign(agent_fd, idlist->keys[j], &sig, &slen,
		    p, CHALLENGE_LEN, NULL, 0) != 0)
			goto exit;

		/* Verify signature */
		if (sshkey_verify(idlist->keys[j], sig, slen, p, CHALLENGE_LEN,
		    NULL, 0, NULL) == 0) {
			ret = PAM_SUCCESS;
			break;
		}
	}

 exit:
	ssh_free_identitylist(idlist);

	return ret;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	UNUSED(pamh);
	UNUSED(flags);
	UNUSED(argc);
	UNUSED(argv);
	return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module _pam_ssh_agent_auth_modstruct = {
	"pam_ssh_agent_auth",
	pam_sm_authenticate,
	pam_sm_setcred,
	NULL,
	NULL,
	NULL,
	NULL,
};
#endif

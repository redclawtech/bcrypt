/*
 * Copyright (c) 2011 Hunter Morris <hunter.morris@smarkets.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ei.h>
#include <erl_comm.h>
#include <unistd.h>

#include "erl_blf.h"

#define dec_int16(s) ((((unsigned char*)(s))[0] << 8) | \
                      (((unsigned char*)(s))[1]))

#define enc_int16(i, s) {((unsigned char*)(s))[0] = ((i) >> 8) & 0xff;  \
        ((unsigned char*)(s))[1] = (i) & 0xff;}

#define BUFSIZE (1 << 16)
#define CMD_SALT "0"
#define CMD_HASHPW "1"

int ts_bcrypt(char *, const char *, const char *);
void encode_salt(char *, u_int8_t *, u_int16_t, u_int8_t);

static int
process_reply(erlang_pid *pid, int cmd, const char *res)
{
    ETERM *result;
    int len, retval;
    byte *buf;
    result = erl_format("{~i, ~w, ~s}", cmd, pid, res);
    len = erl_term_len(result);
    buf = erl_malloc(len);
    erl_encode(result, buf);
    retval = write_cmd(buf, len);
    erl_free_term(result);
    erl_free(buf);
    return retval;
}

static int
process_encode_salt(char *buf, int *index)
{
    int retval = 0;
    ETERM *pattern, *csalt, *lr;
    byte *csalt = NULL;
    long log_rounds = -1;
    int csaltlen = -1;
    char ret[64];
    pattern = erl_format("{Csalt, LogRounds}");
    if (erl_match(pattern, data)) {
        cslt = erl_var_content(pattern, "Csalt");
        csaltlen = ERL_BIN_SIZE(cslt);
        csalt = ERL_BIN_PTR(cslt);
        lr = erl_var_content(pattern, "LogRounds");
        log_rounds = ERL_INT_UVALUE(lr);
        if (16 != csaltlen) {
            retval = process_reply(pid, CMD_SALT, "Invalid salt length");
        } else if (log_rounds < 4 || log_rounds > 31) {
            retval = process_reply(pid, CMD_SALT, "Invalid number of rounds");
        } else {
            encode_salt(ret, (u_int8_t*)csalt, csaltlen, log_rounds);
            retval = process_reply(pid, CMD_SALT, ret);
        }
        erl_free_term(cslt);
        erl_free_term(lr);
    };
    erl_free_term(pattern);
    return retval;
}

static int
process_hashpw(char *buf, int *index)
{
    int retval = 0;
    ETERM *pattern, *pwd, *slt, *pwd_bin, *slt_bin;
    char password[1024];
    char salt[1024];
    char encrypted[1024] = { 0 };

    (void)memset(&password, '\0', sizeof(password));
    (void)memset(&salt, '\0', sizeof(salt));

    pattern = erl_format("{Pass, Salt}");
    if (erl_match(pattern, data)) {
        pwd = erl_var_content(pattern, "Pass");
        pwd_bin = erl_iolist_to_binary(pwd);
        slt = erl_var_content(pattern, "Salt");
        slt_bin = erl_iolist_to_binary(slt);
        if (ERL_BIN_SIZE(pwd_bin) > sizeof(password)) {
            retval = process_reply(pid, CMD_HASHPW, "Password too long");
        } else if (ERL_BIN_SIZE(slt_bin) > sizeof(salt)) {
            retval = process_reply(pid, CMD_HASHPW, "Salt too long");
        } else {
            memcpy(password, ERL_BIN_PTR(pwd_bin), ERL_BIN_SIZE(pwd_bin));
            memcpy(salt, ERL_BIN_PTR(slt_bin), ERL_BIN_SIZE(slt_bin));
            if (ts_bcrypt(encrypted, password, salt)) {
                retval = process_reply(pid, CMD_HASHPW, "Invalid salt");
            } else {
                retval = process_reply(pid, CMD_HASHPW, encrypted);
            }
        }
        erl_free_term(pwd);
        erl_free_term(slt);
        erl_free_term(pwd_bin);
        erl_free_term(slt_bin);
    };
    erl_free_term(pattern);
    return retval;
}

static int
process_command(char *buf, int *index)
{
    int version, arity;
    char cmd;

    *index = 0;

    if (ei_decode_tuple_header(buf, index, &arity) == 0)
	{
        if (arity == 3) {
            if (ei_decode_char(buf, index, cmd) == 0)
            {
                switch (cmd) {
                case CMD_SALT:
                    return process_encode_salt(buf, index);
                case CMD_HASHPW:
                    return process_hashpw(buf, index);
                };
            }
        }
	}
    // Return error tuple here
	return handle_tuple_msg(buf, index, arity);
}

int
main(int argc, char *argv[])
{
    byte buf[BUFSIZE];
    int len;
	int *index = &len;

    ei_init();
    
    while (read_cmd(buf) > 0)
	{
		if (process_command((char *) buf, index))
		{
			fputs("bcrypt ran into an unexpected error.\n", stderr);
			return EXIT_FAILURE;
		}
		write_cmd(buf, len);
	}
    
    return EXIT_SUCCESS;
}

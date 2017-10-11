
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_crypt.h>


#define NGX_HTTP_AUTH_BUF_SIZE  2048


typedef struct {
    ngx_str_t                 passwd_ec;
    ngx_str_t                 passwd;
    ngx_str_t                 user;
} ngx_http_proxyauth_basic_ctx_t;


typedef struct {
    ngx_http_complex_value_t  *realm;
    ngx_http_complex_value_t   user_file;
    ngx_flag_t                 no_unauth_resp;
    ngx_flag_t                 proxy_off;
} ngx_http_proxyauth_basic_loc_conf_t;


static ngx_int_t ngx_http_proxyauth_basic_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxyauth_basic_crypt_handler(ngx_http_request_t *r,
    ngx_http_proxyauth_basic_ctx_t *ctx, ngx_str_t *passwd, ngx_str_t *realm);
static ngx_int_t ngx_http_proxyauth_basic_set_realm(ngx_http_request_t *r,
    ngx_str_t *realm);
static void ngx_http_proxyauth_basic_close(ngx_file_t *file);
static void *ngx_http_proxyauth_basic_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_proxyauth_basic_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_proxyauth_basic_init(ngx_conf_t *cf);
static char *ngx_http_proxyauth_basic_user_file(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_proxyauth_basic_user(ngx_http_request_t *r, 
	ngx_http_proxyauth_basic_ctx_t *ctx);

static ngx_command_t  ngx_http_proxyauth_basic_commands[] = {

    { ngx_string("proxyauth_basic"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxyauth_basic_loc_conf_t, realm),
      NULL },

    { ngx_string("proxyauth_basic_user_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_proxyauth_basic_user_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxyauth_basic_loc_conf_t, user_file),
      NULL },

    { ngx_string("proxyauth_basic_notresp_unauth"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxyauth_basic_loc_conf_t, no_unauth_resp),
      NULL },

    { ngx_string("proxyauth_basic_disable"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxyauth_basic_loc_conf_t, proxy_off),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_proxyauth_basic_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_proxyauth_basic_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_proxyauth_basic_create_loc_conf,   /* create location configuration */
    ngx_http_proxyauth_basic_merge_loc_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_proxyauth_basic_module = {
    NGX_MODULE_V1,
    &ngx_http_proxyauth_basic_module_ctx,       /* module context */
    ngx_http_proxyauth_basic_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_proxyauth_basic_handler(ngx_http_request_t *r)
{
    off_t                            offset;
    ssize_t                          n;
    ngx_fd_t                         fd;
    ngx_int_t                        rc;
    ngx_err_t                        err;
    ngx_str_t                        pwd, realm, user_file;
    ngx_uint_t                       i, level, login, left, passwd;
    ngx_file_t                       file;
    ngx_http_proxyauth_basic_ctx_t       *ctx;
    ngx_http_proxyauth_basic_loc_conf_t  *alcf;
    u_char                           buf[NGX_HTTP_AUTH_BUF_SIZE];
    enum {
        sw_login,
        sw_passwd,
        sw_skip
    } state;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_proxyauth_basic_module);

    if (alcf->proxy_off){
        return NGX_DECLINED;
    }

    if (alcf->realm == NULL || alcf->user_file.value.data == NULL) {
        return NGX_DECLINED;
    }

    if (ngx_http_complex_value(r, alcf->realm, &realm) != NGX_OK) {
        return NGX_ERROR;
    }

    if (realm.len == 3 && ngx_strncmp(realm.data, "off", 3) == 0) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxyauth_basic_module);

    if (ctx && ctx->passwd_ec.data) {
        return ngx_http_proxyauth_basic_crypt_handler(r, ctx, &ctx->passwd_ec,
                                                 &realm);
    }

	ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_proxyauth_basic_ctx_t));
	if (ctx == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	ngx_http_set_ctx(r, ctx, ngx_http_proxyauth_basic_module);

    rc = ngx_http_proxyauth_basic_user(r, ctx);

    if (rc == NGX_DECLINED) {

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "no user/password was provided for basic authentication");

        return ngx_http_proxyauth_basic_set_realm(r, &realm);
    }

    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_complex_value(r, &alcf->user_file, &user_file) != NGX_OK) {
        return NGX_ERROR;
    }

    fd = ngx_open_file(user_file.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

    if (fd == NGX_INVALID_FILE) {
        err = ngx_errno;

        if (err == NGX_ENOENT) {
            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;

        } else {
            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_error(level, r->connection->log, err,
                      ngx_open_file_n " \"%s\" failed", user_file.data);

        return rc;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));

    file.fd = fd;
    file.name = user_file;
    file.log = r->connection->log;

    state = sw_login;
    passwd = 0;
    login = 0;
    left = 0;
    offset = 0;

    for ( ;; ) {
        i = left;

        n = ngx_read_file(&file, buf + left, NGX_HTTP_AUTH_BUF_SIZE - left,
                          offset);

        if (n == NGX_ERROR) {
            ngx_http_proxyauth_basic_close(&file);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (n == 0) {
            break;
        }

        for (i = left; i < left + n; i++) {
            switch (state) {

            case sw_login:
                if (login == 0) {

                    if (buf[i] == '#' || buf[i] == CR) {
                        state = sw_skip;
                        break;
                    }

                    if (buf[i] == LF) {
                        break;
                    }
                }

                if (buf[i] != ctx->user.data[login]) {
                    state = sw_skip;
                    break;
                }

                if (login == ctx->user.len) {
                    state = sw_passwd;
                    passwd = i + 1;
                }

                login++;

                break;

            case sw_passwd:
                if (buf[i] == LF || buf[i] == CR || buf[i] == ':') {
                    buf[i] = '\0';

                    ngx_http_proxyauth_basic_close(&file);

                    pwd.len = i - passwd;
                    pwd.data = &buf[passwd];

                    return ngx_http_proxyauth_basic_crypt_handler(r, ctx, &pwd,
                                                             &realm);
                }

                break;

            case sw_skip:
                if (buf[i] == LF) {
                    state = sw_login;
                    login = 0;
                }

                break;
            }
        }

        if (state == sw_passwd) {
            left = left + n - passwd;
            ngx_memmove(buf, &buf[passwd], left);
            passwd = 0;

        } else {
            left = 0;
        }

        offset += n;
    }

    ngx_http_proxyauth_basic_close(&file);

    if (state == sw_passwd) {
        pwd.len = i - passwd;
        pwd.data = ngx_pnalloc(r->pool, pwd.len + 1);
        if (pwd.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_cpystrn(pwd.data, &buf[passwd], pwd.len + 1);

        return ngx_http_proxyauth_basic_crypt_handler(r, ctx, &pwd, &realm);
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "user \"%V\" was not found in \"%V\"",
                  &ctx->user, &user_file);

    return ngx_http_proxyauth_basic_set_realm(r, &realm);
}


static ngx_int_t
ngx_http_proxyauth_basic_crypt_handler(ngx_http_request_t *r,
    ngx_http_proxyauth_basic_ctx_t *ctx, ngx_str_t *passwd, ngx_str_t *realm)
{
    ngx_int_t   rc;
    u_char     *encrypted;

    rc = ngx_crypt(r->pool, ctx->passwd.data, passwd->data,
                   &encrypted);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "rc: %i user: \"%V\" salt: \"%s\"",
                   rc, &ctx->user, passwd->data);

    if (rc == NGX_OK) {
        if (ngx_strcmp(encrypted, passwd->data) == 0) {
            return NGX_OK;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "encrypted: \"%s\"", encrypted);

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "user \"%V\": password mismatch",
                      &ctx->user);

        return ngx_http_proxyauth_basic_set_realm(r, realm);
    }

    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* rc == NGX_AGAIN */

    if (ctx->passwd_ec.data == NULL) {
        ctx->passwd_ec.len = passwd->len;
        passwd->len++;

        ctx->passwd_ec.data = ngx_pstrdup(r->pool, passwd);
        if (ctx->passwd_ec.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

    }

    /* TODO: add mutex event */

    return rc;
}

static ngx_int_t
ngx_http_proxyauth_basic_user(ngx_http_request_t *r, ngx_http_proxyauth_basic_ctx_t *ctx)
{
	ngx_str_t   auth, encoded;
	ngx_uint_t  len;

	if (ctx->user.len == 0 && ctx->user.data != NULL) {
		return NGX_DECLINED;
	}

	if (r->headers_in.proxyauthorization == NULL) {
		ctx->user.data = (u_char *) "";
		return NGX_DECLINED;
	}

	encoded = r->headers_in.proxyauthorization->value;

	if (encoded.len < sizeof("Basic ") - 1
		|| ngx_strncasecmp(encoded.data, (u_char *) "Basic ",
			sizeof("Basic ") - 1)
		!= 0)
	{
		ctx->user.data = (u_char *) "";
		return NGX_DECLINED;
	}

	encoded.len -= sizeof("Basic ") - 1;
	encoded.data += sizeof("Basic ") - 1;

	while (encoded.len && encoded.data[0] == ' ') {
		encoded.len--;
		encoded.data++;
	}

	if (encoded.len == 0) {
		ctx->user.data = (u_char *) "";
		return NGX_DECLINED;
	}

	auth.len = ngx_base64_decoded_length(encoded.len);
	auth.data = ngx_pnalloc(r->pool, auth.len + 1);
	if (auth.data == NULL) {
		return NGX_ERROR;
	}

	if (ngx_decode_base64(&auth, &encoded) != NGX_OK) {
		ctx->user.data = (u_char *) "";
		return NGX_DECLINED;
	}

	auth.data[auth.len] = '\0';

	for (len = 0; len < auth.len; len++) {
		if (auth.data[len] == ':') {
			break;
		}
	}

	if (len == 0 || len == auth.len) {
		ctx->user.data = (u_char *) "";
		return NGX_DECLINED;
	}

	ctx->user.len = len;
	ctx->user.data = auth.data;
	ctx->passwd.len = auth.len - len - 1;
	ctx->passwd.data = &auth.data[len + 1];

	return NGX_OK;
}

static ngx_int_t
ngx_http_proxyauth_basic_set_realm(ngx_http_request_t *r, ngx_str_t *realm)
{
    size_t   len;
    u_char  *basic, *p;
    ngx_http_proxyauth_basic_loc_conf_t  *alcf;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_proxyauth_basic_module);
    if (alcf->no_unauth_resp) {
        return NGX_HTTP_CLOSE;
    }

    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    len = sizeof("Basic realm=\"\"") - 1 + realm->len;

    basic = ngx_pnalloc(r->pool, len);
    if (basic == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_cpymem(basic, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
    p = ngx_cpymem(p, realm->data, realm->len);
    *p = '"';

    r->headers_out.www_authenticate->hash = 1;
    ngx_str_set(&r->headers_out.www_authenticate->key, "Proxy-Authenticate");
    r->headers_out.www_authenticate->value.data = basic;
    r->headers_out.www_authenticate->value.len = len;

    return 407;
}

static void
ngx_http_proxyauth_basic_close(ngx_file_t *file)
{
    if (ngx_close_file(file->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, file->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", file->name.data);
    }
}


static void *
ngx_http_proxyauth_basic_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_proxyauth_basic_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_proxyauth_basic_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->no_unauth_resp = NGX_CONF_UNSET;
    conf->proxy_off = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_proxyauth_basic_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_proxyauth_basic_loc_conf_t  *prev = parent;
    ngx_http_proxyauth_basic_loc_conf_t  *conf = child;

    if (conf->realm == NULL) {
        conf->realm = prev->realm;
    }

    if (conf->user_file.value.data == NULL) {
        conf->user_file = prev->user_file;
    }

    ngx_conf_merge_value(conf->no_unauth_resp, prev->no_unauth_resp, 0);
    //omit the parent value of proxy_off (not merge)
    if (conf->proxy_off == NGX_CONF_UNSET){
        conf->proxy_off = 0;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_proxyauth_basic_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_proxyauth_basic_handler;

    return NGX_OK;
}


static char *
ngx_http_proxyauth_basic_user_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_proxyauth_basic_loc_conf_t *alcf = conf;

    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t   ccv;

    if (alcf->user_file.value.data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &alcf->user_file;
    ccv.zero = 1;
    ccv.conf_prefix = 1;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

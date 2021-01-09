# Author: Zhang Huangbin <zhb@iredmail.org>

import web
import ldap
import settings
from libs import iredutils, iredpwd
from libs.l10n import TIMEZONES

from libs.ldaplib.core import LDAPWrap
from libs.ldaplib import ldaputils

session = web.config.get('_session')


# Verify bind dn/pw or return LDAP connection object
# Return True if bind success, error message (string) if failed
def verify_bind_dn_pw(dn, password, conn=None):
    dn = web.safestr(dn.strip())
    password = password.strip()

    if not conn:
        _wrap = LDAPWrap()
        conn = _wrap.conn

    uri = settings.ldap_uri

    # Detect STARTTLS support.
    starttls = False
    if uri.startswith('ldaps://'):
        starttls = True

        # Rebuild uri, use ldap:// + STARTTLS (with normal port 389)
        # instead of ldaps:// (port 636) for secure connection.
        uri = uri.replace('ldaps://', 'ldap://')

        # Don't check CA cert
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

    conn_user = ldap.initialize(uri=uri)

    # Set LDAP protocol version: LDAP v3.
    conn_user.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
    try:
        if starttls:
            conn_user.start_tls_s()

        conn_user.bind_s(dn, password)

        user_whoami = conn_user.whoami_s()
        conn_user.unbind_s()

        if user_whoami == "dn:"+dn:
            return (True, )
        else:
            return (False, 'INVALID_CREDENTIALS')
    except Exception as e:
        return (False, repr(e))


# Used for user auth.
def login_auth(username,
               password,
               account_type='user',
               conn=None):
    """Perform full login.

    @username -- full email address
    @password -- account password
    @account_type -- user, admin
    @conn -- ldap connection cursor
    """
    if account_type == 'user':
        dn = ldaputils.rdn_value_to_user_dn(username)
        search_filter = '(&(accountStatus=active)(objectClass=mailUser))'
    elif account_type == 'admin':
        dn = ldaputils.rdn_value_to_admin_dn(username)
        search_filter = '(&(accountStatus=active)(objectClass=mailAdmin))'
    else:
        return (False, 'INVALID_CREDENTIALS')

    if not conn:
        _wrap = LDAPWrap()
        conn = _wrap.conn

    qr = verify_bind_dn_pw(dn=dn, password=password, conn=conn)
    if not qr[0]:
        return qr

    # Update session data to indicate this is an global admin, normal admin,
    # normal mail user (self-service).
    _attrs = ['objectClass', 'mail', 'domainGlobalAdmin',
              'enabledService', 'disabledService', 'accountSetting']
    qr = conn.search_s(dn,
                       ldap.SCOPE_BASE,
                       search_filter,
                       _attrs)

    if not qr:
        # No such account.
        # WARN: Do not return message like 'INVALID USER', it will help
        #       cracker to perdict user existence.
        return (False, 'INVALID_CREDENTIALS')

    (_dn, _ldif) = qr[0]
    _ldif = iredutils.bytes2str(_ldif)

    _object_classes = _ldif.get('objectClass', [])
    _disabled_services = _ldif.get('disabledService', [])

    if _ldif.get('domainGlobalAdmin', ['no'])[0].lower() == 'yes':
        session['is_global_admin'] = True

    if 'mailUser' in _object_classes:
        # Make sure user have 'domainGlobalAdmin=yes' for global
        # admin or 'enabledService=domainadmin' for domain admin.
        if session.get('is_global_admin'):
            session['admin_is_mail_user'] = True

    if session['is_global_admin']:
        if not iredutils.is_allowed_global_admin_login_ip(client_ip=web.ctx.ip):
            session.kill()
            raise web.seeother('/login?msg=NOT_ALLOWED_IP')

    # Language
    lang = _ldif.get('preferredLanguage', [settings.default_language])[0]
    session['lang'] = iredutils.bytes2str(lang)

    #
    # disabledService
    #
    if 'view_mail_log' in _disabled_services:
        session['disable_viewing_mail_log'] = True

    if 'manage_quarantined_mails' in _disabled_services:
        session['disable_managing_quarantined_mails'] = True

    #
    # accountSetting
    #
    _as = ldaputils.account_setting_list_to_dict(_ldif.get('accountSetting', []))
    if 'create_new_domains' in _as:
        session['create_new_domains'] = True

    # per-account time zone
    tz_name = iredutils.bytes2str(_as.get('timezone'))
    if tz_name in TIMEZONES:
        timezone = TIMEZONES[tz_name]
        session['timezone'] = timezone

    return (True, )

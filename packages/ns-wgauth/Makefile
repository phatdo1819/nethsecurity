#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

include $(TOPDIR)/rules.mk

PKG_NAME:=ns-wgauth
PKG_VERSION:=0.0.1
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/ns-wgauth-$(PKG_VERSION)

PKG_LICENSE:=GPL-2.0-only

include $(INCLUDE_DIR)/package.mk

define Package/ns-wgauth
	SECTION:=base
	CATEGORY:=NethSecurity
	TITLE:=Login with user credentials for WireGuard servers
	URL:=https://github.com/NethServer/nethsecurity/
	DEPENDS:=+python3-nethsec +python3-pyotp +nginx-ssl +nftables-json +conntrack +wireguard-tools +qrencode +openssl-util
	PKGARCH:=all
endef

define Package/ns-wgauth/description
	Require the credentials of a local users database, and optionally an OTP code,
	before the peers of a WireGuard server can use the VPN
endef

define Package/ns-wgauth/conffiles
/etc/config/ns-wgauth
endef

# this is required, otherwise compile will fail
define Build/Compile
endef

define Package/ns-wgauth/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
  /etc/init.d/ns-wgauth enable
  /etc/init.d/ns-wgauth restart
fi
exit 0
endef

define Package/ns-wgauth/prerm
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
  /etc/init.d/ns-wgauth stop
  /etc/init.d/ns-wgauth disable
  nft delete table inet ns_wgauth 2>/dev/null
  if [ -f /etc/nginx/conf.d/ns-wgauth.conf ]; then
    rm -f /etc/nginx/conf.d/ns-wgauth.conf
    /etc/init.d/nginx reload
  fi
fi
exit 0
endef

define Package/ns-wgauth/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/www-wgauth
	$(INSTALL_DIR) $(1)/lib/upgrade/keep.d
	$(INSTALL_BIN) ./files/ns-wgauth.py $(1)/usr/sbin/ns-wgauth
	$(INSTALL_CONF) ./files/config $(1)/etc/config/ns-wgauth
	$(INSTALL_BIN) ./files/ns-wgauth.init $(1)/etc/init.d/ns-wgauth
	$(INSTALL_DATA) ./files/www/index.html ./files/www/app.js ./files/www/style.css $(1)/www-wgauth
	$(INSTALL_DATA) ./files/www/manifest.json ./files/www/icon.svg $(1)/www-wgauth
	$(INSTALL_DATA) ./files/www/icon-192.png ./files/www/icon-512.png $(1)/www-wgauth
	# the alerts block the peers whose configuration was copied: they must survive an upgrade
	$(INSTALL_CONF) ./files/ns-wgauth.keep $(1)/lib/upgrade/keep.d/ns-wgauth
endef

$(eval $(call BuildPackage,ns-wgauth))

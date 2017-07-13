package edu.yale.its.tp.cas.client.filter;

import nci.dataman.cas.client.ClientSSOFilter;

/**
 * 增加对之前版本单点登录服务器版本兼容性处理，验证通过后往session中设置key值。
 * 
 * @author xyyue
 * @version 1.5
 * @since 1.5
 */
public class CASFilter_ext extends ClientSSOFilter {
	protected String getLoginURLKey() {
		return "loginUrl";
	}

	protected String getCasServerURLPrefixKey() {
		return "cas.url";
	}

	protected boolean isURLPrefixContainsContext() {
		return false;
	}
}

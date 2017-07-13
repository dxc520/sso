package edu.yale.its.tp.cas.client.filter;

import nci.dataman.cas.client.ClientSSOFilter;

/**
 * ���Ӷ�֮ǰ�汾�����¼�������汾�����Դ�����֤ͨ������session������keyֵ��
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

package nci.dataman.cas.client.filter;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import nci.dataman.cas.client.util.UrlUtils;

/**
 * 单点登录客户端FilterInvocation
 * 
 * @author xyyue
 * @version 1.5
 * @since 1.5
 */
public class FilterInvocation {
	private FilterChain chain;
	private ServletRequest request;
	private ServletResponse response;

	/**
	 * FilterInvocation带参构造器
	 * 
	 * @param request
	 *            请求
	 * @param response
	 *            响应
	 * @param chain
	 *            链
	 */
	public FilterInvocation(ServletRequest request, ServletResponse response,
			FilterChain chain) {
		if ((request == null) || (response == null) || (chain == null)) {
			throw new IllegalArgumentException(
					"Cannot pass null values to constructor");
		}

		if (!(request instanceof HttpServletRequest)) {
			throw new IllegalArgumentException(
					"Can only process HttpServletRequest");
		}

		if (!(response instanceof HttpServletResponse)) {
			throw new IllegalArgumentException(
					"Can only process HttpServletResponse");
		}

		this.request = request;
		this.response = response;
		this.chain = chain;
	}

	public FilterChain getChain() {
		return chain;
	}

	/**
	 * Indicates the URL that the user agent used for this request.
	 * <P>
	 * The returned URL does <b>not</b> reflect the port number determined from
	 * a {@link org.acegisecurity.util.PortResolver}.
	 * </p>
	 * 
	 * @return the full URL of this request
	 */
	public String getFullRequestUrl() {
		return UrlUtils.buildFullRequestUrl((HttpServletRequest) request);
	}

	public HttpServletRequest getHttpRequest() {
		return (HttpServletRequest) request;
	}

	public HttpServletResponse getHttpResponse() {
		return (HttpServletResponse) response;
	}

	public ServletRequest getRequest() {
		return request;
	}

	/**
	 * Obtains the web application-specific fragment of the URL.
	 * 
	 * @return the URL, excluding any server name, context path or servlet path
	 */
	public String getRequestUrl() {
		return UrlUtils.buildRequestUrl((HttpServletRequest) request);
	}

	public ServletResponse getResponse() {
		return response;
	}

	/**
	 * 输出请求url
	 * 
	 * @return 请求url
	 */
	public String toString() {
		return "FilterInvocation: URL: " + getRequestUrl();
	}
}

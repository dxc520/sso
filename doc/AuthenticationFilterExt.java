package org.nci.cas.client.authentication;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.jasig.cas.client.authentication.DefaultGatewayResolverImpl;
import org.jasig.cas.client.authentication.GatewayResolver;
import org.jasig.cas.client.util.AbstractCasFilter;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.validation.Assertion;

/**
 * 增加对之前版本单点登录服务器版本兼容性处理，验证通过后往session中设置key值。
 * 
 * @author jijiezh
 * @version 1.5
 * @since 1.5
 */
public class AuthenticationFilterExt extends AbstractCasFilter {
	/**
	 * 参数名：propertiesFile
	 */
	public final static String PROPERTIESFILE_INIT_PARAM = "propertiesFile";
	/**
	 * 参数名：enabled
	 */
	public final static String ENABLED_INIT_PARAM = "enabled";
	/**
	 * 是否开启单点登录过滤
	 */
	private String enabled;
	/**
	 * The URL to the CAS Server login.
	 */
	private String casServerLoginUrl;

	/**
	 * Whether to send the renew request or not.
	 */
	private boolean renew = false;

	/**
	 * Whether to send the gateway request or not.
	 */
	private boolean gateway = false;

	private GatewayResolver gatewayStorage = new DefaultGatewayResolverImpl();
	private static Properties p;

	private void loadProperties(String propertiesFile) {
		InputStream is = AuthenticationFilterExt.class.getClassLoader()
				.getResourceAsStream(propertiesFile);
		if (is != null) {
			try {
				p = new Properties();
				p.load(is);
			} catch (IOException e) {
				log.error("Loading prperties config ERROR!", e);
			} finally {
				try {
					is.close();
				} catch (IOException e) {
					log.error("Closing prperties config ERROR!", e);
				}
			}
		}
		setServerName(p.getProperty("serverName", null));
		setCasServerLoginUrl(p.getProperty("loginUrl", null));
		log.trace("Loaded CasServerLoginUrl parameter: "
				+ this.casServerLoginUrl);
	}

	protected void initInternal(final FilterConfig filterConfig)
			throws ServletException {
		if (!isIgnoreInitConfiguration()) {
			super.initInternal(filterConfig);
			enabled = filterConfig.getInitParameter(ENABLED_INIT_PARAM);
			String propertiesFile = filterConfig
					.getInitParameter(PROPERTIESFILE_INIT_PARAM);
			if (propertiesFile != null) {
				loadProperties(propertiesFile);
			}

			setRenew(parseBoolean(getPropertyFromInitParams(filterConfig,
					"renew", "false")));
			log.trace("Loaded renew parameter: " + this.renew);
			setGateway(parseBoolean(getPropertyFromInitParams(filterConfig,
					"gateway", "false")));
			log.trace("Loaded gateway parameter: " + this.gateway);

			final String gatewayStorageClass = getPropertyFromInitParams(
					filterConfig, "gatewayStorageClass", null);

			if (gatewayStorageClass != null) {
				try {
					this.gatewayStorage = (GatewayResolver) Class.forName(
							gatewayStorageClass).newInstance();
				} catch (final Exception e) {
					log.error(e, e);
					throw new ServletException(e);
				}
			}
		}
	}

	public void init() {
		super.init();
		CommonUtils.assertNotNull(this.casServerLoginUrl,
				"casServerLoginUrl cannot be null.");
	}

	private static final String CAS_FILTER_USER = "edu.yale.its.tp.cas.client.filter.user";

	public final void doFilter(final ServletRequest servletRequest,
			final ServletResponse servletResponse, final FilterChain filterChain)
			throws IOException, ServletException {
		final HttpServletRequest request = (HttpServletRequest) servletRequest;
		final HttpServletResponse response = (HttpServletResponse) servletResponse;
		/**
		 * 如果单点登录配置为不可用，直接跳过单点登录拦截
		 */
		if ("false".equals(enabled)) {
			filterChain.doFilter(request, response);
			return;
		}
		final HttpSession session = request.getSession(false);
		final Assertion assertion = session != null ? (Assertion) session
				.getAttribute(CONST_CAS_ASSERTION) : null;

		if (assertion != null) {
			session.setAttribute(CAS_FILTER_USER, assertion.getPrincipal()
					.getName());
			filterChain.doFilter(request, response);
			return;
		}

		final String serviceUrl = constructServiceUrl(request, response);
		final String ticket = CommonUtils.safeGetParameter(request,
				getArtifactParameterName());
		final boolean wasGatewayed = this.gatewayStorage.hasGatewayedAlready(
				request, serviceUrl);

		if (CommonUtils.isNotBlank(ticket) || wasGatewayed) {
			filterChain.doFilter(request, response);
			return;
		}

		final String modifiedServiceUrl;

		log.debug("no ticket and no assertion found");
		if (this.gateway) {
			log.debug("setting gateway attribute in session");
			modifiedServiceUrl = this.gatewayStorage.storeGatewayInformation(
					request, serviceUrl);
		} else {
			modifiedServiceUrl = serviceUrl;
		}

		if (log.isDebugEnabled()) {
			log.debug("Constructed service url: " + modifiedServiceUrl);
		}

		final String urlToRedirectTo = CommonUtils.constructRedirectUrl(
				this.casServerLoginUrl, getServiceParameterName(),
				modifiedServiceUrl, this.renew, this.gateway);

		if (log.isDebugEnabled()) {
			log.debug("redirecting to \"" + urlToRedirectTo + "\"");
		}

		response.sendRedirect(urlToRedirectTo);
	}

	public final void setRenew(final boolean renew) {
		this.renew = renew;
	}

	public final void setGateway(final boolean gateway) {
		this.gateway = gateway;
	}

	public final void setCasServerLoginUrl(final String casServerLoginUrl) {
		this.casServerLoginUrl = casServerLoginUrl;
	}

	public final void setGatewayStorage(final GatewayResolver gatewayStorage) {
		this.gatewayStorage = gatewayStorage;
	}

}

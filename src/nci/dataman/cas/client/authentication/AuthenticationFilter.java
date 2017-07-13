package nci.dataman.cas.client.authentication;

import java.io.IOException;

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

import nci.dataman.cas.client.util.ParamUtil;

/**
 * —È÷§filter
 * 
 * @author xyyue
 * @version 1.5
 * @since 1.5
 */
public class AuthenticationFilter extends AbstractCasFilter {

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

	private long casValidTime;

	private String casRedirectUrl;

	protected void initInternal(final FilterConfig filterConfig)
			throws ServletException {
		if (!isIgnoreInitConfiguration()) {
			super.initInternal(filterConfig);
			setCasServerLoginUrl(getPropertyFromInitParams(filterConfig,
					"casServerLoginUrl", null));
			log.trace("Loaded CasServerLoginUrl parameter: "
					+ this.casServerLoginUrl);
			setRenew(parseBoolean(getPropertyFromInitParams(filterConfig,
					"renew", "false")));
			log.trace("Loaded renew parameter: " + this.renew);
			setGateway(parseBoolean(getPropertyFromInitParams(filterConfig,
					"gateway", "false")));
			log.trace("Loaded gateway parameter: " + this.gateway);
			setCasValidTime(Long.parseLong(getPropertyFromInitParams(
					filterConfig, "casValidTime", "0")));
			log.trace("Loaded casValidTime parameter: " + this.casValidTime);
			setCasRedirectUrl(getPropertyFromInitParams(filterConfig,
					"casRedirectUrl", null));
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
		setCasServerLoginUrl(ParamUtil.getPropertyFromProperties(
				"casServerLoginUrl", null));
		log.trace("Loaded CasServerLoginUrl parameter: "
				+ this.casServerLoginUrl);
		setRenew(parseBoolean(ParamUtil.getPropertyFromProperties("renew",
				"false")));
		log.trace("Loaded renew parameter: " + this.renew);
		setGateway(parseBoolean(ParamUtil.getPropertyFromProperties("gateway",
				"false")));
		log.trace("Loaded gateway parameter: " + this.gateway);
		setCasValidTime(Long.parseLong(ParamUtil.getPropertyFromProperties(
				"casValidTime", "0")));
		log.trace("Loaded casValidTime parameter: " + this.casValidTime);

		setServerName(ParamUtil.getPropertyFromProperties("serverName", null));
		setService(ParamUtil.getPropertyFromProperties("service", null));
		setArtifactParameterName(ParamUtil.getPropertyFromProperties(
				"artifactParameterName", "ticket"));
		setServiceParameterName(ParamUtil.getPropertyFromProperties(
				"serviceParameterName", "service"));
		setEncodeServiceUrl(parseBoolean(ParamUtil.getPropertyFromProperties(
				"encodeServiceUrl", "true")));
		setCasRedirectUrl(ParamUtil.getPropertyFromProperties("casRedirectUrl",
				null));
		CommonUtils.assertNotNull(this.casServerLoginUrl,
				"casServerLoginUrl cannot be null.");
		super.init();
	}

	public final void doFilter(final ServletRequest servletRequest,
			final ServletResponse servletResponse, final FilterChain filterChain)
			throws IOException, ServletException {
		final HttpServletRequest request = (HttpServletRequest) servletRequest;
		final HttpServletResponse response = (HttpServletResponse) servletResponse;
		final HttpSession session = request.getSession(false);
		final Assertion assertion = session != null ? (Assertion) session
				.getAttribute(CONST_CAS_ASSERTION) : null;

		final String serviceUrl = constructServiceUrl(request, response);
		final String ticket = CommonUtils.safeGetParameter(request,
				getArtifactParameterName());
		final boolean wasGatewayed = this.gatewayStorage.hasGatewayedAlready(
				request, serviceUrl);

		String CAS_FILTER_USER = "edu.yale.its.tp.cas.client.filter.user";
		if (assertion != null) {
			if (!isReceiptvalid(assertion)) {
				response.sendRedirect(casRedirectUrl);
				return;
			} else if (!isTheSameUser(request, assertion)) {
				response.sendRedirect(casRedirectUrl);
				return;
			} else {
				session.setAttribute(CAS_FILTER_USER, assertion.getPrincipal()
						.getName());
				session.setAttribute("SSO_USERNAME", assertion
						.getPrincipal().getName());
				filterChain.doFilter(request, response);
				return;
			}

		}

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

	/**
	 * when the last valid time of the receipt greater than casValidTime return
	 * false else return true
	 * 
	 * @param receipt
	 * @return true if valid, false otherwise
	 */
	private boolean isReceiptvalid(Assertion assertion) {
		if (assertion != null) {
			if ((System.currentTimeMillis()
					- assertion.getValidFromDate().getTime() <= casValidTime)
					|| casValidTime <= 0) {
				return true;
			}
		}
		return false;
	}

	private boolean isTheSameUser(ServletRequest request, Assertion assertion) {
		HttpSession session = ((HttpServletRequest) request).getSession();
		String oldUser = "";
		Object object = null;
		if (session != null) {
			object = session.getAttribute("_const_cas_assertion_");
			if (object != null) {
				Assertion oldAssertion = (Assertion) object;
				oldUser = oldAssertion.getPrincipal().getName();
			}
		}
		if (oldUser == null || oldUser.length() == 0) {
			// do nothing
		} else if (oldUser.equals(assertion.getPrincipal().getName())) {
			return true;
		}
		return false;
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

	public void setCasValidTime(long casValidTime) {
		this.casValidTime = casValidTime;
	}

	public void setCasRedirectUrl(String casRedirectUrl) {
		this.casRedirectUrl = casRedirectUrl;
	}

}

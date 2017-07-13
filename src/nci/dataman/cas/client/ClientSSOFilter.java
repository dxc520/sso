package nci.dataman.cas.client;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.configuration.CompositeConfiguration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.commons.configuration.SystemConfiguration;
import org.apache.commons.lang.StringUtils;
import org.jasig.cas.client.session.SingleSignOutFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;

import nci.dataman.cas.client.authentication.AuthenticationFilter;
import nci.dataman.cas.client.env.EnvironmentConfiguration;
import nci.dataman.cas.client.filter.FilterInvocation;
import nci.dataman.cas.client.filter.VirtualFilterChain;
import nci.dataman.cas.client.util.CasConfigConstant;
import nci.dataman.cas.client.validation.Cas20ProxyReceivingTicketValidationFilter;

/**
 * 单点登录客户端Filter
 * 
 * @author xyyue
 * @version 1.5
 * @since 1.5
 */
public class ClientSSOFilter implements Filter {

	private static Logger logger = LoggerFactory.getLogger(ClientSSOFilter.class);

	/**
	 * casServerLoginUrl的key配置
	 * 
	 * @return String
	 */
	protected String getLoginURLKey() {
		return "casServerLoginUrl";
	}

	/**
	 * casServerUrlPrefix的key配置
	 * 
	 * @return String
	 */
	protected String getCasServerURLPrefixKey() {
		return "casServerUrlPrefix";
	}

	/**
	 * serverName的key配置
	 * 
	 * @return String
	 */
	protected String getServerNameKey() {
		return "serverName";
	}

	protected String casLoginURL;
	protected String casServerName;
	protected String casServerURLPrefix;
	protected String excludePatterns;
	protected boolean excludeStartwithCTX = false;
	protected String reqEncoding;

	public String getCasLoginURL() {
		return casLoginURL;
	}

	public void setCasLoginURL(String casLoginURL) {
		this.casLoginURL = casLoginURL;
	}

	public String getCasServerName() {
		return casServerName;
	}

	public void setCasServerName(String casServerName) {
		this.casServerName = casServerName;
	}

	public String getCasServerURLPrefix() {
		return casServerURLPrefix;
	}

	public void setCasServerURLPrefix(String casServerURLPrefix) {
		this.casServerURLPrefix = casServerURLPrefix;
	}

	public String getExcludePatterns() {
		return excludePatterns;
	}

	public void setExcludePatterns(String excludePatterns) {
		this.excludePatterns = excludePatterns;
	}

	/**
	 * casServerUrlPrefix配置中是否默认含有上下文，如果没有则修正。<br>
	 * 针对办公已有配置兼容性处理，实际应该配置有上下文。
	 * 
	 * @return boolean
	 */
	protected boolean isURLPrefixContainsContext() {
		return true;
	}

	/**
	 * 是否开启单点登录过滤
	 */
	private boolean enabled;
	private Filter[] filters;
	CompositeConfiguration config = null;
	private static String[] excludes = null;
	private static PathMatcher matcher = new AntPathMatcher();

	public void init(FilterConfig filterConfig) throws ServletException {
		enabled = Boolean.valueOf(filterConfig.getInitParameter(CasConfigConstant.ENABLED_INIT_PARAM));

		String propertiesFile = filterConfig.getInitParameter(CasConfigConstant.PROPERTIESFILE_INIT_PARAM);
		if (propertiesFile != null) {
			config = loadConfiguration(propertiesFile);
		}
		String casServerURL = config.getString(getCasServerURLPrefixKey());
		casServerURLPrefix = casServerURL;

		String encoding = filterConfig.getInitParameter("encoding");
		if (StringUtils.isNotEmpty(encoding)) {
			this.reqEncoding = encoding;
		}
		String loginURL = config.getString(getLoginURLKey());
		if (StringUtils.isNotEmpty(loginURL)) {
			this.casLoginURL = loginURL;
		} else {
			this.casLoginURL = casServerURL
					+ (StringUtils.isNotEmpty(casServerURL) && casServerURL.endsWith("/") ? "" : "/") + "login";
		}
		casServerName = config.getString(getServerNameKey());

		excludePatterns = config.getString(CasConfigConstant.KEY_EXCLUDE_PATTERNS);
		if (excludePatterns != null && excludePatterns.length() > 0) {
			excludes = excludePatterns.split(",");
		}
		String startwithCXT = config.getString("exludeStartwithContext");
		if (StringUtils.isNotEmpty(startwithCXT)) {
			excludeStartwithCTX = Boolean.valueOf(startwithCXT);
		}

		filters = obtainAllDefinedFilters(null);
		filterConfig.getServletContext().setAttribute("CAS16_SERVER_URL", casServerURLPrefix);
	}

	private CompositeConfiguration loadConfiguration(String fileName) {
		CompositeConfiguration config = new CompositeConfiguration();
		config.addConfiguration(new EnvironmentConfiguration());
		config.addConfiguration(new SystemConfiguration());
		try {
			PropertiesConfiguration props = new PropertiesConfiguration();
			props.setFileName(fileName);
			props.setDelimiterParsingDisabled(true);
			props.load();
			config.addConfiguration(props);
		} catch (ConfigurationException e) {
			logger.error(e.getMessage());
		}
		return config;
	}

	/**
	 * 初始化单点登录需要的过滤器 通过无参数init调用
	 * 
	 * @param filterConfig
	 *            true:使用cas.properties文件初始化数据，false:使用统一配置
	 * @return Filter[]
	 * @throws ServletException
	 */
	private Filter[] obtainAllDefinedFilters(FilterConfig filterConfig) throws ServletException {

		if (!isURLPrefixContainsContext()) {
			casServerURLPrefix += CasConfigConstant.DEFAULT_CONTEXT;
		}

		AuthenticationFilter authFilter = new AuthenticationFilter();
		Cas20ProxyReceivingTicketValidationFilter validatorFilter = new Cas20ProxyReceivingTicketValidationFilter();

		authFilter.setServerName(this.casServerName);
		authFilter.setCasServerLoginUrl(this.casLoginURL);
		authFilter.setEncodeServiceUrl(true);
		authFilter.setArtifactParameterName(CasConfigConstant.KEY_PARAM_TICKET);
		authFilter.setServiceParameterName(CasConfigConstant.KEY_PARAM_SERVICE);
		authFilter.setGateway(false);
		authFilter.setIgnoreInitConfiguration(false);
		authFilter.setRenew(false);

		validatorFilter.setExceptionOnValidationFailure(true);
		validatorFilter.setRedirectAfterValidation(true);
		validatorFilter.setUseSession(true);
		validatorFilter.setExceptionOnValidationFailure(true);
		validatorFilter.setCasServerUrlPrefix(casServerURLPrefix);
		validatorFilter.setExceptionOnValidationFailure(true);
		validatorFilter.setServerName(this.casServerName);
		validatorFilter.setArtifactParameterName(CasConfigConstant.KEY_PARAM_TICKET);
		validatorFilter.setServiceParameterName(CasConfigConstant.KEY_PARAM_SERVICE);
		validatorFilter.setEncodeServiceUrl(true);
		validatorFilter.getValidatorInstance(casServerURLPrefix);
		validatorFilter.setService(null);

		return new Filter[] { new SingleSignOutFilter(), authFilter, validatorFilter };
	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain fc)
			throws IOException, ServletException {
		if (!enabled) {
			fc.doFilter(request, response);
			return;
		}
		if (StringUtils.isNotEmpty(this.reqEncoding)) {
			request.setCharacterEncoding(reqEncoding);
		}

		String path = !excludeStartwithCTX ? ((HttpServletRequest) request).getServletPath()
				: ((HttpServletRequest) request).getRequestURI();
		if (excludes != null) {
			for (String exludePattern : excludes) {
				if (matcher.match(exludePattern, path)) {
					fc.doFilter(request, response);
					return;
				}
			}
		}
		FilterInvocation fi = new FilterInvocation(request, response, fc);
		if (filters.length == 0) {
			if (logger.isDebugEnabled()) {
				logger.debug(fi.getRequestUrl() + " has an empty filter list");
			}
			fc.doFilter(request, response);
			return;
		}
		new VirtualFilterChain(fi, filters).doFilter(fi.getRequest(), fi.getResponse());
	}

	public void destroy() {
		for (int i = 0; i < filters.length; i++) {
			if (filters[i] != null) {
				if (logger.isDebugEnabled()) {
					logger.debug("Destroying Filter defined in ApplicationContext: '" + filters[i].toString() + "'");
				}
				filters[i].destroy();
			}
		}
	}
}

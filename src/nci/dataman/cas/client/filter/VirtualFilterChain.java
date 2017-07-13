package nci.dataman.cas.client.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 单点登录客户端FilterChain
 * 
 * @author jijiezh
 * @version 1.5
 * @since 1.5
 */
public class VirtualFilterChain implements FilterChain {
	private static Logger logger = LoggerFactory
			.getLogger(VirtualFilterChain.class);
	private FilterInvocation fi;
	private Filter[] additionalFilters;
	private int currentPosition = 0;

	/**
	 * VirtualFilterChain带参构造函数
	 * 
	 * @param filterInvocation
	 *            Filter数组
	 * @param additionalFilters
	 *            添加的过滤类
	 */
	public VirtualFilterChain(FilterInvocation filterInvocation,
			Filter[] additionalFilters) {
		this.fi = filterInvocation;
		this.additionalFilters = additionalFilters;
	}

	public void doFilter(ServletRequest request, ServletResponse response)
			throws IOException, ServletException {
		if (currentPosition == additionalFilters.length) {
			if (logger.isDebugEnabled()) {
				logger.debug(fi.getRequestUrl()
						+ " reached end of additional filter chain; proceeding with original chain");
			}
			fi.getChain().doFilter(request, response);
		} else {
			currentPosition++;
			if (logger.isDebugEnabled()) {
				logger.debug(fi.getRequestUrl() + " at position "
						+ currentPosition + " of " + additionalFilters.length
						+ " in additional filter chain; firing Filter: '"
						+ additionalFilters[currentPosition - 1] + "'");
			}
			additionalFilters[currentPosition - 1].doFilter(request, response,
					this);
		}
	}

}

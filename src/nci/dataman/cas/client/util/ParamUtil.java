package nci.dataman.cas.client.util;

import java.io.IOException;

import org.apache.commons.configuration.CompositeConfiguration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.commons.configuration.SystemConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.io.support.ResourcePatternResolver;

import nci.dataman.cas.client.env.EnvironmentConfiguration;

/**
 * 配置参数工具类
 * 
 * @author xyyue
 * @since 1.5.0
 * @version 1.0
 */
public class ParamUtil {

	private static Logger logger = LoggerFactory.getLogger(ParamUtil.class);
	private static String propertiesFile = "cas.properties";

	private static CompositeConfiguration config;

	static {
		if (existPropertiesFile()) {
			loadConfiguration(propertiesFile);
		}
	}

	private static void loadConfiguration(String fileName) {
		if (propertiesFile == null)
			return;
		config = new CompositeConfiguration();
		config.addConfiguration(new EnvironmentConfiguration());
		config.addConfiguration(new SystemConfiguration());
		try {
			config.addConfiguration(new PropertiesConfiguration(fileName));
		} catch (ConfigurationException e) {
			logger.error("加载属性配置文件错误!", e);
		}
	}

	public static final String getPropertyFromProperties(
			final String propertyName, final String defaultValue) {
		if (config == null) {
			loadConfiguration(propertiesFile);
		}
		if (config != null) {
			return config.getString(propertyName, defaultValue);
		}
		return defaultValue;
	}

	public static final boolean existPropertiesFile() {
		ResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
		Resource rs = resolver
				.getResource(ResourcePatternResolver.CLASSPATH_ALL_URL_PREFIX
						+ propertiesFile);
		try {
			return rs.getFile().exists();
		} catch (IOException e) {
			return false;
		}
	}
}

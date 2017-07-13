package nci.dataman.cas.client.env;

import java.util.Iterator;
import java.util.Map;

import org.apache.commons.configuration.AbstractConfiguration;
import org.apache.commons.lang.StringUtils;

public class EnvironmentConfiguration extends AbstractConfiguration {
	private Map<String, String> environment;

	public EnvironmentConfiguration() {
		environment = System.getenv();
	}

	public boolean isEmpty() {
		return environment.isEmpty();
	}

	public boolean containsKey(String key) {
		if (StringUtils.isEmpty(key)) {
			return false;
		}
		return environment.containsKey(key)
				|| environment.containsKey(key.toUpperCase());
	}

	public Object getProperty(String key) {
		if (StringUtils.isEmpty(key))
			return null;
		String value = environment.get(key);
		return StringUtils.isNotEmpty(value) ? value : environment.get(key
				.toUpperCase());
	}

	@SuppressWarnings("rawtypes")
	public Iterator getKeys() {
		return environment.keySet().iterator();
	}

	@Override
	protected void addPropertyDirect(String key, Object value) {
		throw new UnsupportedOperationException("Configuration is read-only!");
	}

}

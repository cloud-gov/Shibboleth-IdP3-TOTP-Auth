package net.kvak.shibboleth.totpauth.authn.impl;

import javax.annotation.Nonnull;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.warrenstrange.googleauth.GoogleAuthenticator;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

public class TotpSeedValidator {
	/** Class logger. */
	@Nonnull
	@NotEmpty
	private final Logger log = LoggerFactory.getLogger(RegisterNewToken.class);

  public boolean validateToken(GoogleAuthenticator gAuth, String seed, int token) {
		log.debug("Entering validatetoken");

		int[] allowedSeedLengths = {16, 32};

		if (ArrayUtils.contains(allowedSeedLengths, seed.length()) && StringUtils.isAlphanumeric(seed)) {
			log.debug("Authorize {} - {} ", seed, token);
			return gAuth.authorize(seed, token);
		}
		log.debug("Token code validation failed. Seed value does not match expected lengths: {}", allowedSeedLengths.toString());
		return false;
	}
}

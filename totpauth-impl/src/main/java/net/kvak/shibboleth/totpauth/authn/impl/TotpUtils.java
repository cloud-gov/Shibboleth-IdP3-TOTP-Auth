package net.kvak.shibboleth.totpauth.authn.impl;

import java.util.List;

import javax.annotation.Nonnull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.AbstractContextMapper;
import org.springframework.ldap.filter.EqualsFilter;

import com.warrenstrange.googleauth.GoogleAuthenticator;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

@SuppressWarnings("deprecation")
public class TotpUtils {

	private TotpSeedValidator totpSeedValidator;
	
	/** Class logger. */
	@Nonnull
	@NotEmpty
	private final Logger log = LoggerFactory.getLogger(RegisterNewToken.class);

	GoogleAuthenticator gAuth;

	String userAttribute;

	LdapTemplate ldapTemplate;

	public TotpUtils() {
		this.gAuth = new GoogleAuthenticator();
		this.totpSeedValidator = new TotpSeedValidator();
	}

	public boolean validateToken(String seed, int token) {
		return this.totpSeedValidator.validateToken(gAuth, seed, token);
	}

	@SuppressWarnings({ "unchecked", "rawtypes", "unused" })
	private String fetchDn(String username) {

		String dn = "";
		EqualsFilter f = new EqualsFilter(userAttribute, username);
		log.debug("{} Trying to find user {} dn from ldap with filter {}", username, f.encode());


		List result = ldapTemplate.search(DistinguishedName.EMPTY_PATH, f.toString(), new AbstractContextMapper() {
			protected Object doMapFromContext(DirContextOperations ctx) {
				return ctx.getDn().toString();
			}
		});
		if (result.size() == 1) {
			log.debug("{} User {} relative DN is: {}", username, (String) result.get(0));
			dn = (String) result.get(0);
		} else {
			log.warn("{} User not found or not unique. DN size: {}", result.size());
			throw new RuntimeException("User not found or not unique");
		}

		return dn;
	}

}

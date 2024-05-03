package net.kvak.shibboleth.totpauth.authn.impl;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import org.apache.commons.lang.RandomStringUtils;
import static org.mockito.Mockito.*;

import com.warrenstrange.googleauth.GoogleAuthenticator;

import org.junit.Before;
import org.junit.Test;

public class TotpSeedValidatorTest {

    private GoogleAuthenticator gAuthMock;
    private TotpSeedValidator totpSeedValidator;

    @Before
    public void setUp() throws Exception {
        totpSeedValidator = new TotpSeedValidator();
        gAuthMock = mock(GoogleAuthenticator.class);
        when(gAuthMock.authorize(anyString(), anyInt())).thenReturn(true);
    }


    @Test
    public void Test16CharacterSeed() {
        int length = 16;
        boolean useLetters = true;
        boolean useNumbers = false;
        String seed = RandomStringUtils.random(length, useLetters, useNumbers);

        assertTrue(
            "16 character seed should be accepted",
            totpSeedValidator.validateToken(this.gAuthMock, seed, 123456)
        );
    }

    @Test
    public void Test32CharacterSeed() {
        int length = 32;
        boolean useLetters = true;
        boolean useNumbers = false;
        String seed = RandomStringUtils.random(length, useLetters, useNumbers);

        assertTrue(
            "32 character seed should be accepted",
            totpSeedValidator.validateToken(this.gAuthMock, seed, 123456)
        );
    }

    @Test
    public void TestBadCharacterSeed() {
        int length = 8;
        boolean useLetters = true;
        boolean useNumbers = false;
        String seed = RandomStringUtils.random(length, useLetters, useNumbers);

        assertFalse(
            "9 character seed should not be accepted",
            totpSeedValidator.validateToken(this.gAuthMock, seed, 123456)
        );
    }
}

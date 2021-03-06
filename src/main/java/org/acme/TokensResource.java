package org.acme;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

import org.jboss.logging.Logger;

@Path("/token")
public class TokensResource {

    @Inject
    Logger logger;

    private static RSAPublicKey publicRsaKey;
    private static RSAPrivateKey privateRsaKey;

    static {

		KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            
            //Initialize key size
            keyPairGenerator.initialize(2048);
            // Generate the key pair
            KeyPair keyPair = keyPairGenerator.genKeyPair();

            // Create KeyFactory and RSA Keys Specs
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
            RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(keyPair.getPrivate(), RSAPrivateKeySpec.class);

            // Generate (and retrieve) RSA Keys from the KeyFactory using Keys Specs
            publicRsaKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
            privateRsaKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public String generate() throws Exception {

		JWTClaimsSet.Builder claimsSet = createClaimSet();

		// Create the JWE header and specify:
		// RSA-OAEP as the encryption algorithm
		// 128-bit AES/GCM as the encryption method
		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);

		// Initialized the EncryptedJWT object
		EncryptedJWT jwt = new EncryptedJWT(header, claimsSet.build());

		// Create an RSA encrypted with the specified public RSA key
		RSAEncrypter encrypter = new RSAEncrypter(publicRsaKey);

		// Doing the actual encryption
		jwt.encrypt(encrypter);

		// Serialize to JWT compact form
		String jwtString = jwt.serialize();
		return jwtString;
    }

    private JWTClaimsSet.Builder createClaimSet() {
        JWTClaimsSet.Builder claimsSet = new JWTClaimsSet.Builder();
		claimsSet.issuer("Issuer Claim");
		claimsSet.subject("JWE-Authentication-Example");

		//User specified claims
        claimsSet.claim("active", true);
		claimsSet.claim("appId", "230919131512092005");
		claimsSet.claim("userId", "4431d8dc-2f69-4057-9b83-a59385d18c03");
		claimsSet.claim("groups", Arrays.asList("Admin", "User"));
		claimsSet.claim("applicationType", "App");
		claimsSet.claim("clientRemoteAddress", "192.168.1.3");
		
		claimsSet.expirationTime(new Date(new Date().getTime() + 1000 * 60 * 10));
		claimsSet.notBeforeTime(new Date());
		claimsSet.jwtID(UUID.randomUUID().toString());
        return claimsSet;
    }


    @POST
    @Path("/introspect")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public String introspect(@FormParam("token") String token, @QueryParam("mock") boolean mock) throws Exception {
        logger.infof("introspect: %s", token);
        logger.infof("mock: %s", mock);
        if(mock) {
            JWTClaimsSet.Builder claimsSet = createClaimSet();
            return claimsSet.build().toString();
        }
        // In order to read back the data from the token using your private RSA key:
		// parse the JWT text string using EncryptedJWT object
		EncryptedJWT jwt = EncryptedJWT.parse(token);

		// Create a decrypter with the specified private RSA key
		RSADecrypter decrypter = new RSADecrypter(privateRsaKey);

		// Doing the decryption
		jwt.decrypt(decrypter);
        Payload payload = jwt.getPayload();
        return payload.toBase64URL().decodeToString();
    }

    @GET
    @Path("/introspect")
    @Produces(MediaType.APPLICATION_JSON)
    public String decryptGET(@QueryParam("token") String token, @QueryParam("mock") boolean mock) throws Exception {
        return introspect(token, mock);
    }
    
}
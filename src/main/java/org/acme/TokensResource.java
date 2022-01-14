package org.acme;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

@Path("/tokens")
public class TokensResource {

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
    @Path("/jwe")
    @Produces(MediaType.TEXT_PLAIN)
    public String generate() throws Exception {


		JWTClaimsSet.Builder claimsSet = new JWTClaimsSet.Builder();
		claimsSet.issuer("Issuer Claim");
		claimsSet.subject("JWE-Authentication-Example");

		//User specified claims
		claimsSet.claim("appId", "230919131512092005");
		claimsSet.claim("userId", "4431d8dc-2f69-4057-9b83-a59385d18c03");
		claimsSet.claim("groups", Arrays.asList("Admin", "User"));
		claimsSet.claim("applicationType", "App");
		claimsSet.claim("clientRemoteAddress", "192.168.1.3");
		
		claimsSet.expirationTime(new Date(new Date().getTime() + 1000 * 60 * 10));
		claimsSet.notBeforeTime(new Date());
		claimsSet.jwtID(UUID.randomUUID().toString());

		System.out.println("Claim Set : \n" + claimsSet.build());

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

    @GET
    @Path("/decrypt/jwe")
    @Produces(MediaType.TEXT_PLAIN)
    public String decrypt(@QueryParam("token") String token) throws Exception {
    
		// In order to read back the data from the token using your private RSA key:
		// parse the JWT text string using EncryptedJWT object
		EncryptedJWT jwt = EncryptedJWT.parse(token);

		// Create a decrypter with the specified private RSA key
		RSADecrypter decrypter = new RSADecrypter(privateRsaKey);

		// Doing the decryption
		jwt.decrypt(decrypter);
        return jwt.getPayload().toBase64URL().decodeToString();
    }

    @POST
    @Path("/introspect")
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, Object> decrypt() throws Exception {
        JWTClaimsSet.Builder claimsSet = new JWTClaimsSet.Builder();
		
		claimsSet.expirationTime(new Date(new Date().getTime() + 1000 * 60 * 10));
		claimsSet.notBeforeTime(new Date());
        claimsSet.issueTime(new Date());
        claimsSet.audience("Custom Aud");
		claimsSet.claim("active", true);

        Map<String, String> permissions = new HashMap<>();
        permissions.put("resource_id", "90ccc6fc-b296-4cd1-881e-089e1ee15957");
        permissions.put("resource_name", "Hello World Resource");
        claimsSet.claim("permissions", Collections.singletonList(permissions));
		
        return claimsSet.build().toJSONObject(false);
    }
}
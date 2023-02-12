package org.example;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.codec.binary.Base64;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.function.Function;

/*
    openssl genrsa -out secret_key.pem 2048
    openssl pkcs8 -topk8 -inform PEM -outform PEM -in secret_key.pem -out private_key.pem -nocrypt
    openssl rsa -in secret_key.pem -pubout -outform PEM -out public_key.pem
 */
public class JwtSignVerifyX599 {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        Key privateKey = loadPrivateKey(new FileInputStream("./keys/private_key.pem"));
        Key publicKey = loadPublicKey(new FileInputStream("./keys/public_key.pem"));

        System.out.println(publicKey);
        System.out.println(privateKey);

        String jwt = Jwts.builder()
                .setSubject("paul.simon")
                .signWith(SignatureAlgorithm.RS256, privateKey)
                .compact();

        System.out.println(jwt);

        String subject = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(jwt).getBody().getSubject();
        System.out.println(subject);

    }

    private static Key loadKey(InputStream in, Function<byte[], Key> keyParser) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(in))) {
            String line;
            StringBuilder content = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                if (!(line.contains("BEGIN") || line.contains("END"))) {
                    content.append(line).append('\n');
                }
            }
            byte[] encoded = Base64.decodeBase64(content.toString());
            return keyParser.apply(encoded);
        }
    }

    public static Key loadPrivateKey(InputStream in) throws IOException, NoSuchAlgorithmException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return loadKey(in, bytes -> {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
            try {
                RSAPrivateKey key = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
                return key;
            } catch (InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public static Key loadPublicKey(InputStream in) throws IOException, NoSuchAlgorithmException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return loadKey(in, bytes -> {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
            try {
                X509EncodedKeySpec spec =
                        new X509EncodedKeySpec(bytes);
                return keyFactory.generatePublic(spec);
            } catch (InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }
        });
    }

}

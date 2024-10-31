/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.example.security;

import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.util.Base64;

public class SessionKeyManager {
    
    private Map<String, SecretKey> sessionKeys = new HashMap<>();
    private Map<String, PublicKey> userPublicKeys = new HashMap<>();
    private Map<String, PrivateKey> userPrivateKeys = new HashMap<>();

    // Kullanıcıların public ve private anahtarlarını ekleyelim (örnek amaçlı)
    public void addUserKeys(String userId, PublicKey publicKey, PrivateKey privateKey) {
        userPublicKeys.put(userId, publicKey);
        userPrivateKeys.put(userId, privateKey);
    }

    // Oturum başlatma ve AES anahtarını kullanıcılar için şifreleme
    public void initiateSession(String user1, String user2) throws Exception {
        SecretKey aesKey = EncryptionUtils.generateAESKey();
        PublicKey user1PublicKey = userPublicKeys.get(user1);
        PublicKey user2PublicKey = userPublicKeys.get(user2);
        
        byte[] encryptedAESKeyForUser1 = EncryptionUtils.encryptAESKeyWithRSA(aesKey, user1PublicKey);
        byte[] encryptedAESKeyForUser2 = EncryptionUtils.encryptAESKeyWithRSA(aesKey, user2PublicKey);

        sessionKeys.put(user1 + "-" + user2, aesKey);
        sessionKeys.put(user2 + "-" + user1, aesKey);

        // Şifreli anahtarları saklama işlemi (kullanıcıya özel alanlarda saklanabilir)
        System.out.println("User 1 için şifrelenmiş AES anahtarı: " + Base64.getEncoder().encodeToString(encryptedAESKeyForUser1));
        System.out.println("User 2 için şifrelenmiş AES anahtarı: " + Base64.getEncoder().encodeToString(encryptedAESKeyForUser2));
    }

    // Mesajı şifreleme
    public byte[] encryptMessage(String sender, String receiver, String message) throws Exception {
        SecretKey aesKey = sessionKeys.get(sender + "-" + receiver);
        return EncryptionUtils.encryptMessageWithAES(message, aesKey);
    }

    // Mesajı çözme
    public String decryptMessage(String receiver, String sender, byte[] encryptedMessage) throws Exception {
        SecretKey aesKey = sessionKeys.get(receiver + "-" + sender);
        return EncryptionUtils.decryptMessageWithAES(encryptedMessage, aesKey);
    }
}



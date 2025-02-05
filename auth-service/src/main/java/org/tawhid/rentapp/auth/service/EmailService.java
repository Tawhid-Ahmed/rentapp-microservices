package org.tawhid.rentapp.auth.service;

import org.springframework.stereotype.Service;

@Service
public class EmailService {
    public void sendOtp(String to, String otp){
        System.out.println("Sending OTP" +otp+ "to: " + to);
    }
    public void sendResetToken(String to, String resetToken) {
        System.out.println("Sending password reset token " + resetToken + " to " + to);
    }
}

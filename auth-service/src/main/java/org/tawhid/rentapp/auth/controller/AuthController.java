package org.tawhid.rentapp.auth.controller;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.tawhid.rentapp.auth.model.User;
import org.tawhid.rentapp.auth.service.EmailService;
import org.tawhid.rentapp.auth.service.UserService;
import org.tawhid.rentapp.auth.util.JwtUtil;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private JwtUtil jwtUtil;

    // Registration endpoint
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegistrationRequest request) {
        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(request.getPassword());
        User savedUser = userService.registerUser(user);
        // Send OTP (stubbed)
        emailService.sendOtp(savedUser.getEmail(), savedUser.getOtp());
        return ResponseEntity.ok("Registration successful. Please check your email for OTP verification.");
    }

    // OTP verification endpoint
    @PostMapping("/verify")
    public ResponseEntity<String> verifyOtp(@RequestBody OtpVerificationRequest request) {
        boolean verified = userService.verifyOtp(request.getEmail(), request.getOtp());
        if (verified) {
            return ResponseEntity.ok("Email verified successfully.");
        }
        return ResponseEntity.badRequest().body("Invalid OTP or email.");
    }

    // Login endpoint: Returns a JWT token on successful authentication
    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@RequestBody LoginRequest request) {
        return userService.authenticate(request.getEmail(), request.getPassword())
                .map(user -> {
                    String token = jwtUtil.generateToken(user.getEmail());
                    return ResponseEntity.ok(new JwtResponse(token));
                })
                .orElseGet(() -> ResponseEntity.badRequest().body(new JwtResponse("Invalid credentials or email not verified.")));
    }


    // --- New Endpoints for Milestone 2 ---

    /**
     * Request password reset by generating a reset token and sending it via email.
     */
    @PostMapping("/requestPasswordReset")
    public ResponseEntity<String> requestPasswordReset(@RequestBody PasswordResetRequest request) {
        return userService.requestPasswordReset(request.getEmail())
                .map(user -> {
                    // Send the reset token via email
                    emailService.sendResetToken(user.getEmail(), user.getResetToken());
                    return ResponseEntity.ok("Password reset token sent to your email.");
                })
                .orElseGet(() -> ResponseEntity.badRequest().body("Email not found."));
    }

    /**
     * Reset the password using the reset token.
     */
    @PostMapping("/resetPassword")
    public ResponseEntity<String> resetPassword(@RequestBody ResetPasswordRequest request) {
        boolean reset = userService.resetPassword(request.getEmail(), request.getResetToken(), request.getNewPassword());
        if (reset) {
            return ResponseEntity.ok("Password reset successfully.");
        }
        return ResponseEntity.badRequest().body("Invalid reset token or token expired.");
    }

    /**
     * Refresh JWT token by accepting a valid token and issuing a new one.
     * (In production, you might separate access and refresh tokens.)
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestHeader("Authorization") String authHeader) {
        // Expecting header format: "Bearer <token>"
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            if (jwtUtil.validateToken(token)) {
                String email = jwtUtil.getEmailFromToken(token);
                String newToken = jwtUtil.generateToken(email);
                return ResponseEntity.ok(new JwtResponse(newToken));
            }
        }
        return ResponseEntity.badRequest().body("Invalid token.");
    }


    // DTO Classes


    public static class RegistrationRequest {
        private String email;
        private String password;

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }


    public static class OtpVerificationRequest {
        private String email;
        private String otp;

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getOtp() {
            return otp;
        }

        public void setOtp(String otp) {
            this.otp = otp;
        }
    }


    public static class LoginRequest {
        private String email;
        private String password;

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }


    public static class JwtResponse {
        private final String token;

        public JwtResponse(String token) {
            this.token = token;
        }


        public String getToken() {
            return token;
        }
    }

    public static class PasswordResetRequest {
        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        private String email;
    }

    public static class ResetPasswordRequest {
        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getResetToken() {
            return resetToken;
        }

        public void setResetToken(String resetToken) {
            this.resetToken = resetToken;
        }

        public String getNewPassword() {
            return newPassword;
        }

        public void setNewPassword(String newPassword) {
            this.newPassword = newPassword;
        }

        private String email;
        private String resetToken;
        private String newPassword;
    }
}

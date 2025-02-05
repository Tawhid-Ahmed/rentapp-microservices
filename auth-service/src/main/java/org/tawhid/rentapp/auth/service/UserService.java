package org.tawhid.rentapp.auth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.tawhid.rentapp.auth.model.User;
import org.tawhid.rentapp.auth.repository.UserRepository;

import java.time.Instant;
import java.util.Optional;
import java.util.Random;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public User registerUser(User user) {
        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
            throw new RuntimeException("User already exists with email: " + user.getEmail());
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        String otp = String.valueOf(100000 + new Random().nextInt(900000));
        user.setOtp(otp);
        user.setVerified(false);
        return userRepository.save(user);
    }

    public boolean verifyOtp(String email, String otp) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isPresent() && otp.equals(userOptional.get().getOtp())) {
            User user = userOptional.get();
            user.setVerified(true);
            user.setOtp(null);
            userRepository.save(user);
            return true;
        }
        return false;
    }

    public Optional<User> authenticate(String email, String rawPassword) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isPresent() && userOptional.get().isVerified()) {
            if (passwordEncoder.matches(rawPassword, userOptional.get().getPassword())) {
                return userOptional;
            }
        }
        return Optional.empty();
    }

    /**
     * Generates a reset token and expiry time, saves them on the user, and returns the updated user.
     */
    public Optional<User> requestPasswordReset(String email) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            // Generate a reset token (here we use a random 6-digit number; in production use a secure random string)
            String resetToken = String.valueOf(100000 + new Random().nextInt(900000));
            // Set expiry time (for example, 15 minutes from now)
            Long expiry = Instant.now().toEpochMilli() + (15 * 60 * 1000);
            user.setResetToken(resetToken);
            user.setResetTokenExpiry(expiry);
            userRepository.save(user);
            return Optional.of(user);
        }
        return Optional.empty();
    }

    /**
     * Resets the password if the provided reset token is valid and not expired.
     */
    public boolean resetPassword(String email, String resetToken, String newPassword) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            Long now = Instant.now().toEpochMilli();
            if (user.getResetToken() != null &&
                    user.getResetToken().equals(resetToken) &&
                    user.getResetTokenExpiry() != null &&
                    user.getResetTokenExpiry() >= now) {
                // Token is valid: update password and clear reset token fields
                user.setPassword(passwordEncoder.encode(newPassword));
                user.setResetToken(null);
                user.setResetTokenExpiry(null);
                userRepository.save(user);
                return true;
            }
        }
        return false;
    }
}

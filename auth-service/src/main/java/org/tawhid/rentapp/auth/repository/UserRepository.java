package org.tawhid.rentapp.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.tawhid.rentapp.auth.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
}

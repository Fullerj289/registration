package com.fuller.registration.appuser;

import com.fuller.registration.AppUser;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
@Transactional(readOnly = true)
public interface AppUserRepository {

    Optional<AppUser> findByEmail(String email);
}

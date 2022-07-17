package com.project.demo.appuser;

import com.project.demo.registration.token.ConfirmationToken;
import com.project.demo.registration.token.ConfirmationTokenService;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@AllArgsConstructor
public class AppUserService implements UserDetailsService {

    private static final String USER_NOT_FOUND_MESSAGE = "User with email %s not found";
    private final AppUserRepository appUserRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final ConfirmationTokenService confirmationTokenService;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return appUserRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException(String.format(USER_NOT_FOUND_MESSAGE, email)));
    }

    public String singUpUser(AppUser user) {
        Optional<AppUser> appUserOptional = appUserRepository.findByEmail(user.getEmail());

        if (appUserOptional.isEmpty()) {
            String encodedPassword = bCryptPasswordEncoder.encode(user.getPassword());
            user.setPassword(encodedPassword);

            appUserRepository.save(user);

            return generateAndSaveConfirmationToken(user);
        }
        if (compareUsers(appUserOptional.get(), user) && !appUserOptional.get().isEnabled()) {

            return generateAndSaveConfirmationToken(appUserOptional.get());
        }

        throw new IllegalStateException("email already taken");
    }

    public int enableAppUser(String email) {
        return appUserRepository.enableAppUser(email);
    }

    public boolean compareUsers(AppUser savedUser, AppUser userToCompare) {
        return savedUser.getLastName().equals(userToCompare.getLastName())
                && savedUser.getUsername().equals(userToCompare.getUsername())
                && bCryptPasswordEncoder.matches(userToCompare.getPassword(), savedUser.getPassword());
    }

    public String generateAndSaveConfirmationToken(AppUser user) {
        String token = UUID.randomUUID().toString();
        ConfirmationToken confirmationToken = new ConfirmationToken(
                token,
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(15),
                user
        );

        confirmationTokenService.saveConfirmationToken(confirmationToken);

        return token;
    }

}

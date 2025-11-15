package com.projectManagementApp.services.impl;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.projectManagementApp.config.JwtHelper;
import com.projectManagementApp.entities.PasswordResetToken;
import com.projectManagementApp.entities.User;
import com.projectManagementApp.globalException.InvalidOtpException;
import com.projectManagementApp.globalException.InvalidTokenException;
import com.projectManagementApp.globalException.OtpExpiredException;
import com.projectManagementApp.globalException.ResourceNotFoundException;
import com.projectManagementApp.repositories.PasswordResetTokenRepository;
import com.projectManagementApp.repositories.UserRepository;
import com.projectManagementApp.services.UserService;
import org.springframework.beans.factory.annotation.Value;

import jakarta.mail.internet.MimeMessage;
import jakarta.transaction.Transactional;

@Service
public class UserServiceImpl implements UserService{
	
	@Autowired
	private JwtHelper jwtHelper;


	@Value("${frontend.url}")
        private String frontendUrl;
	
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	@Autowired  
	private UserRepository userRepository;
	
	@Autowired
	private PasswordResetTokenRepository passwordResetTokenRepository;
	
	@Autowired
	private JavaMailSender javaMailSender;

	@Override
	public User findUserByEmail(String email) {
		User user = this.userRepository.findByEmail(email).orElseThrow(()->
		new ResourceNotFoundException("User not found"));
		
		return user;
	}

	@Override
	public User findUserById(Long userId) {
		User user = this.userRepository.findById(userId).orElseThrow(()->
			new ResourceNotFoundException("User not found with " + userId)
		);
		return user;
	}

	@Override
	public User updateUsersProjectSize(User user, int number) {
		user.setProjectSize(user.getProjectSize()+number);
		
		return this.userRepository.save(user);
	}

	@Override
	public User findUserProfileByJwt() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String email = authentication.getName();
		User user = this.userRepository.findByEmail(email).orElseThrow(()-> 
		new ResourceNotFoundException("User not found provided Jwt " ));
		return user;
	}
	
@Override
public String forgotPassword(String email) throws ResourceNotFoundException {
    try {
        log.info("Starting password reset process for email: {}", email);
        
        User user = this.userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email " + email));
        
        log.info("User found, generating OTP and token");
        
        Random rand = new Random();
        int otp = 1000 + rand.nextInt(9000);
        String token = UUID.randomUUID().toString();
        LocalDateTime expirationTime = LocalDateTime.now().plusMinutes(10);
        
        PasswordResetToken resetToken = new PasswordResetToken();
        resetToken.setOtp(otp);
        resetToken.setToken(token);
        resetToken.setUser(user);
        resetToken.setExpirationTime(expirationTime);
        passwordResetTokenRepository.save(resetToken);
        
        log.info("Token saved, preparing to send email");

        // Create HTML email with styling
        MimeMessage message = javaMailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
        
        helper.setFrom("devinsightt@gmail.com"); // ADD THIS - Important!
        helper.setTo(email);
        helper.setSubject("🔐 Password Reset Request - Action Required");
        
        log.info("Email helper configured, creating HTML content");
        
        String htmlContent = createPasswordResetHtmlContent(user.getUsername(), otp, token);
        helper.setText(htmlContent, true);
        
        log.info("Attempting to send email to: {}", email);
        javaMailSender.send(message);
        log.info("Email sent successfully to: {}", email);
        
        return token;
        
    } catch (ResourceNotFoundException e) {
        log.error("User not found: {}", email);
        throw e;
    } catch (MessagingException e) {
        log.error("Email messaging error for {}: {}", email, e.getMessage(), e);
        throw new RuntimeException("Failed to send email: " + e.getMessage(), e);
    } catch (MailException e) {
        log.error("Mail sending failed for {}: {}", email, e.getMessage(), e);
        throw new RuntimeException("Failed to send email: " + e.getMessage(), e);
    } catch (Exception e) {
        log.error("Unexpected error in forgotPassword for {}: {}", email, e.getMessage(), e);
        throw new RuntimeException("An unexpected error occurred: " + e.getMessage(), e);
    }
}
	private String createPasswordResetHtmlContent(String username, int otp, String token) {
	    String resetUrl = frontendUrl+"/reset-password?token=" + token;
	    
	    return "<html>" +
	           "<head>" +
	           "<title>Password Reset</title>" +
	           "</head>" +
	           "<body style='font-family: Arial, sans-serif; padding: 20px;'>" +
	           "<div style='max-width: 400px; margin: 0 auto; border: 1px solid #ccc; padding: 20px;'>" +
	           "<h2>Password Reset</h2>" +
	           "<p>Hello " + username + ",</p>" +
	           "<p>Your verification code is: <strong>" + otp + "</strong></p>" +
	           "<p><a href='" + resetUrl + "' style='background: blue; color: white; padding: 10px 20px; text-decoration: none;'>Reset Password</a></p>" +
	           "<p>This code expires in 10 minutes.</p>" +
	           "<p>If you can't click the button, copy this link: " + resetUrl + "</p>" +
	           "</div>" +
	           "</body>" +
	           "</html>";
	}
	
	@Override
	@Transactional
	public String resetPassword(String token, Integer otp, String newPassword)
	        throws InvalidTokenException, OtpExpiredException, InvalidOtpException {
	    
	    PasswordResetToken resetToken = passwordResetTokenRepository.findByToken(token);

	    if (resetToken == null) {
	        throw new InvalidTokenException("Invalid token. Please request a new OTP.");
	    }

	    if (resetToken.getExpirationTime().isBefore(LocalDateTime.now())) {
	        throw new OtpExpiredException("OTP has expired. Please request a new one.");
	    }

	    if (!resetToken.getOtp().equals(otp)) {
	        throw new InvalidOtpException("Invalid OTP. Please try again.");
	    }

	    try {
	        // Get user ID from token
	        Long userId = resetToken.getUser().getUserId();
	        
	        // Fetch a fresh instance of the user entity
	        User user = userRepository.findById(userId)
	            .orElseThrow(() -> new RuntimeException("User not found"));
	        
	        // Update password
	        user.setPassword(passwordEncoder.encode(newPassword));
	        
	        // If version is null, initialize it (safety check)
//	        if (user.getVersion() == null) {
//	            user.setVersion(0L);
//	        }
	        
	        // Save user
	        userRepository.save(user);
	        
	        // Delete token after successful save
	        passwordResetTokenRepository.delete(resetToken);
	        
	        return "Password has been successfully updated.";
	    } catch (Exception e) {
	        throw new RuntimeException("Failed to update password: " + e.getMessage(), e);
	    }
	}

	  public Optional<User> findByEmail(String email) {
	        Optional<User> byEmail = userRepository.findByEmail(email);
	        return byEmail;
	    }
	  
	  
	  public User registerUser(User newUser) {
	      return userRepository.save(newUser);
	    }


}

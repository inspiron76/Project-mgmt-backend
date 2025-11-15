
package com.projectManagementApp.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.projectManagementApp.entities.User;
import com.projectManagementApp.globalException.InvalidOtpException;
import com.projectManagementApp.globalException.InvalidTokenException;
import com.projectManagementApp.globalException.OtpExpiredException;
import com.projectManagementApp.globalException.ResourceNotFoundException;
import com.projectManagementApp.payloads.ApiResponse;
import com.projectManagementApp.payloads.ForgotPasswordRequest;
import com.projectManagementApp.payloads.ResetPasswordRequest;
import com.projectManagementApp.services.UserService;

@RestController
@RequestMapping("/api/users")
@CrossOrigin(origins = {"http://localhost:5173", "https://splendorous-zuccutto-0b577e.netlify.app/","https://projectmanagentapp-6.onrender.com/"}, allowCredentials = "true")
public class UserController {
	
	@Autowired
	private UserService userService;
	
	@GetMapping("/profile")
	public ResponseEntity<ApiResponse<User>> getUserProfile() {
	    try {
	        User user = this.userService.findUserProfileByJwt();
	        ApiResponse<User> apiResponse = new ApiResponse<>();
	        apiResponse.setData(user);
	        apiResponse.setMessage("User profile fetched successfully");
	        apiResponse.setSuccess(true);
	        return ResponseEntity.ok(apiResponse);
	    } catch (Exception e) {
	        ApiResponse<User> errorResponse = new ApiResponse<>();
	        errorResponse.setMessage("Failed to fetch user profile: " + e.getMessage());
	        errorResponse.setSuccess(false);
	        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
	    }
	}

	@PostMapping("/forgot-password")
	public ResponseEntity<ApiResponse<String>> forgotPassword(@RequestBody ForgotPasswordRequest request) {
	    try {
	        // Validate input
	        if (request.getEmail() == null || request.getEmail().trim().isEmpty()) {
	            ApiResponse<String> errorResponse = new ApiResponse<>();
	            errorResponse.setSuccess(false);
	            errorResponse.setMessage("Email is required");
	            return ResponseEntity.badRequest().body(errorResponse);
	        }

	        // Email format validation
	        if (!isValidEmail(request.getEmail())) {
	            ApiResponse<String> errorResponse = new ApiResponse<>();
	            errorResponse.setSuccess(false);
	            errorResponse.setMessage("Invalid email format");
	            return ResponseEntity.badRequest().body(errorResponse);
	        }

	        String token = userService.forgotPassword(request.getEmail());
	        
	        ApiResponse<String> response = new ApiResponse<>();
	        response.setSuccess(true);
	        response.setMessage("Password reset OTP sent successfully to your email");
	        response.setData(token);
	        return ResponseEntity.ok(response);
	            
	    } catch (ResourceNotFoundException e) {
	        ApiResponse<String> errorResponse = new ApiResponse<>();
	        errorResponse.setSuccess(false);
	        errorResponse.setMessage(e.getMessage());
	        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
	            
	    } catch (RuntimeException e) {
	        ApiResponse<String> errorResponse = new ApiResponse<>();
	        errorResponse.setSuccess(false);
	        errorResponse.setMessage("Failed to send reset email. Please try again later.");
	        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
	            
	    } //catch (Exception e) {
	    //     ApiResponse<String> errorResponse = new ApiResponse<>();
	    //     errorResponse.setSuccess(false);
	    //     errorResponse.setMessage("An unexpected error occurred. Please try again later.");
	    //     return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
	    // }
	}

	@PostMapping("/reset-password")
	public ResponseEntity<ApiResponse<String>> resetPassword(@RequestParam String token,@RequestBody ResetPasswordRequest request) {
	    try {
	        // Validate input
	        if (token == null || token.trim().isEmpty()) {
	            ApiResponse<String> errorResponse = new ApiResponse<>();
	            errorResponse.setSuccess(false);
	            errorResponse.setMessage("Token is required");
	            return ResponseEntity.badRequest().body(errorResponse);
	        }

	        if (request.getOtp() == null) {
	            ApiResponse<String> errorResponse = new ApiResponse<>();
	            errorResponse.setSuccess(false);
	            errorResponse.setMessage("OTP is required");
	            return ResponseEntity.badRequest().body(errorResponse);
	        }

	        if (request.getNewPassword() == null || request.getNewPassword().trim().isEmpty()) {
	            ApiResponse<String> errorResponse = new ApiResponse<>();
	            errorResponse.setSuccess(false);
	            errorResponse.setMessage("New password is required");
	            return ResponseEntity.badRequest().body(errorResponse);
	        }

	        // Password strength validation
	        if (request.getNewPassword().length() < 6) {
	            ApiResponse<String> errorResponse = new ApiResponse<>();
	            errorResponse.setSuccess(false);
	            errorResponse.setMessage("Password must be at least 6 characters long");
	            return ResponseEntity.badRequest().body(errorResponse);
	        }

	        String result = userService.resetPassword(token, request.getOtp(), request.getNewPassword());
	        
	        ApiResponse<String> response = new ApiResponse<>();
	        response.setSuccess(true);
	        response.setMessage(result);
	        return ResponseEntity.ok(response);
	            
	    } catch (InvalidTokenException e) {
	        ApiResponse<String> errorResponse = new ApiResponse<>();
	        errorResponse.setSuccess(false);
	        errorResponse.setMessage(e.getMessage());
	        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
	            
	    } catch (OtpExpiredException e) {
	        ApiResponse<String> errorResponse = new ApiResponse<>();
	        errorResponse.setSuccess(false);
	        errorResponse.setMessage(e.getMessage());
	        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
	            
	    } catch (InvalidOtpException e) {
	        ApiResponse<String> errorResponse = new ApiResponse<>();
	        errorResponse.setSuccess(false);
	        errorResponse.setMessage(e.getMessage());
	        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
	            
	    } catch (RuntimeException e) {
	        ApiResponse<String> errorResponse = new ApiResponse<>();
	        errorResponse.setSuccess(false);
	        errorResponse.setMessage("Failed to reset password. Please try again later.");
	        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
	            
	    } catch (Exception e) {
	        ApiResponse<String> errorResponse = new ApiResponse<>();
	        errorResponse.setSuccess(false);
	        errorResponse.setMessage("An unexpected error occurred. Please try again later.");
	        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
	    }
	}

	// Helper method for email validation
	private boolean isValidEmail(String email) {
	    String emailRegex = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";
	    return email.matches(emailRegex);
	}
}

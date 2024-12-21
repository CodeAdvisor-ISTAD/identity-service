# CodeAdvisors Identity Service 🔒

![CodeAdvisors Logo](http://167.172.78.79:8090/api/v1/files/preview?fileName=b5d01918-2824-48d7-83e0-fb557ce6bd73_2024-12-21T18-28-24.856529397.jpg)

## Overview 🌐
The **Identity Service** is a core component of the **CodeAdvisors** platform that handles user authentication, authorization, and identity management. It supports features like user registration, password recovery, and secure login with OAuth2.

## Features ✨
- **User Registration**: Create new accounts.
- **Login**: Authenticate users securely.
- **Password Recovery**: Send OTP for password resets.
- **OAuth2 Integration**: Secure authorization.
- **Email Notifications**: Send emails for OTP and account-related updates.
- **Template-Based UI**: Pre-built HTML templates for easy testing.

---

## Templates for Testing UI 🖥️

The Identity Service includes the following HTML templates located in the `src/main/resources/templates` directory:

1. **forget-password.html**:  
   Used to test the password recovery flow by entering an email address.

2. **home.html**:  
   A simple landing page, displayed after a successful login.

3. **login.html**:  
   A login page for users to authenticate into the service.

4. **otp.html**:  
   Used to test OTP (One-Time Password) functionality for verification.

5. **register.html**:  
   A registration page for creating new user accounts.

6. **reset-password.html**:  
   Used to reset a password after an OTP is confirmed.

7. **reset-pwd-otp.html**:  
   A page to enter the OTP for verifying password reset requests.

---

## Technologies Used ⚙️

- **Spring Boot**: Backend framework for building RESTful APIs and authentication.
- **Spring Security**: For managing OAuth2 and resource server functionality.
- **JPA with PostgreSQL**: For storing user credentials and data.
- **Spring Mail**: For sending OTP and other email notifications.
- **Thymeleaf**: For rendering HTML templates.
- **Oauth2**: For secure authorization and authentication.

---

## Prerequisites 📦

1. **JDK 21**: Required for building and running the service.
2. **PostgreSQL Database**: Ensure it is set up with the necessary configurations:
    - URL: `jdbc:postgresql://localhost:5432/oauth2`
    - Username: `postgres`
    - Password: `123456`

3. **Email Configuration**: Ensure SMTP is properly configured to send emails.
4. **Eureka Server**: Required for service registration and discovery.

---

## Running the Service 🚀

1. Clone the repository:
   ```bash
   git clone https://github.com/CodeAdvisor-ISTAD/identity-service.git
   cd identity-service
   ```

2. Build the project:
   ```bash
   ./gradlew build
   ```

3. Start the application:
   ```bash
   ./gradlew bootRun
   ```

4. Access the service via `http://localhost:9090`.

---

## Testing the UI 🧪

1. **Setup**: Start the service and ensure the database and SMTP are running.
2. **Access Templates**: Open the following endpoints in your browser:
    - **Login**: `http://localhost:9090/login`
    - **Registration**: `http://localhost:9090/register`
    - **Password Recovery**: `http://localhost:9090/forget-password`
3. **Test Flows**:
    - **Login Flow**: Use valid credentials to access the home page.
    - **Password Recovery Flow**: Request a password reset and verify the OTP.
    - **Registration Flow**: Register a new user and log in.

---

## License 📜
This project is licensed under the MIT License. See the LICENSE file for more details.

---

Built with ❤️ by the CodeAdvisors Team.

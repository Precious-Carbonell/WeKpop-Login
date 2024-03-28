## Features

- User registration - Users can sign up by providing a username and password. The password is securely hashed using the bcrypt library before storing it in the database.

- Secure login: Users can log in securely with their registered username and password. Passwords are hashed and compared to the stored hashed passwords for authentication.

- User details display: Upon successful login, an admin user (username: admin, password: 12345) can view all registered user details, including usernames and hashed passwords, in a separate window.

- Edit and delete users: Admin users have the ability to edit and delete user details directly from the user details window. This provides flexibility in managing user accounts.

## Install Dependencies
- pip install bcrypt (for secure pass hashing)
- pip install customtkinter (for custom gui styling thingy)

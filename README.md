# BugBounty Platform

A Django-based bug bounty platform where users can join as hunters or clients. Clients can publish bounties, and hunters can submit bugs. Each bounty offers a reward upon successful bug submission.

## Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Environment Variables](#environment-variables)
  - [Running the Server](#running-the-server)
- [API Documentation](#api-documentation)
- [Contributing](#contributing)
- [License](#license)

## Features

- User registration with email and password
- Role-based access control (Hunter or Client)
- JWT authentication
- OTP verification during registration
- Clients can create bounties
- Hunters can submit bugs
- Reward system for accepted bugs

## Tech Stack

- Python 3.x
- Django
- Django REST Framework
- PostgreSQL (or any preferred database)
- JWT for authentication
- `python-dotenv` for environment variables

## Getting Started

### Prerequisites

- Python 3.x installed on your machine
- PostgreSQL database (or modify settings for your preferred database)
- Git (to clone the repository)

### Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/yourusername/bugbounty-platform.git
   cd bugbounty-platform
   ```

2. **Create a virtual environment**

   ```bash
   python -m venv venv
   ```

3. **Activate the virtual environment**

   - On Windows:

     ```bash
     venv\Scripts\activate
     ```

   - On macOS/Linux:

     ```bash
     source venv/bin/activate
     ```

4. **Install the dependencies**

   ```bash
   pip install -r requirements.txt
   ```

### Environment Variables

1. **Create a `.env` file in the project root**

   ```dotenv
   DEBUG=True
   SECRET_KEY=your-secret-key
   DATABASE_NAME=yourdatabase
   DATABASE_USER=yourusername
   DATABASE_PASSWORD=yourpassword
   DATABASE_HOST=localhost
   DATABASE_PORT=5432
   ```

   Replace the values with your actual database credentials and a secure `SECRET_KEY`.

2. **Update `settings.py` to load from `.env`**

   Ensure that your `settings.py` is configured to read from the `.env` file (this is already set up if you followed the instructions above).

### Running the Server

1. **Apply Migrations**

   ```bash
   python manage.py migrate
   ```

2. **Create a Superuser (Optional, for admin access)**

   ```bash
   python manage.py createsuperuser
   ```

3. **Run the Development Server**

   ```bash
   python manage.py runserver
   ```

4. **Access the Application**

   - API endpoints are accessible at `http://localhost:8000/`
   - Admin panel is accessible at `http://localhost:8000/admin/` (if you created a superuser)

## API Documentation

API endpoints:

- **User Registration**: `POST /api/register/`
- **User Login**: `POST /api/token/`
- **Token Refresh**: `POST /api/token/refresh/`
- **OTP Verification**: `POST /api/verify-otp/`
- **Bounties**:
  - List/Create: `GET/POST /api/bounties/`
  - Retrieve/Update/Delete: `GET/PUT/DELETE /api/bounties/<id>/`
- **Bugs**:
  - List/Create: `GET/POST /api/bugs/`
  - Retrieve/Update/Delete: `GET/PUT/DELETE /api/bugs/<id>/`

_For detailed API usage and request/response formats, refer to the [API Documentation](API_DOCS.md) (you can create this file with detailed docs)._

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/YourFeature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin feature/YourFeature`)
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

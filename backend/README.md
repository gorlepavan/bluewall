# BlueWall Backend

A secure FastAPI backend with role-based access control and TOTP authentication.

## Features

- **FastAPI Framework**: Modern, fast web framework for building APIs
- **Role-Based Access Control**: Admin and Officer roles with different permission levels
- **Two-Factor Authentication**: TOTP support using Google Authenticator
- **JWT Authentication**: Secure token-based authentication
- **SQLAlchemy ORM**: Database abstraction and management
- **Production Ready**: Docker support, logging, and health checks

## Project Structure

```
backend/
├── main.py              # FastAPI application entry point
├── requirements.txt     # Python dependencies
├── Dockerfile.backend  # Docker configuration
├── README.md           # This file
├── db/
│   ├── session.py      # Database session management
│   └── models.py       # Database models
└── auth/
    └── security.py     # Authentication and security functions
```

## Quick Start

### Prerequisites

- Python 3.11+
- pip
- Virtual environment (recommended)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd BlueWall/backend
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   ```bash
   # Copy the example file
   cp .env.example .env
   
   # Edit .env with your configuration
   # At minimum, change SECRET_KEY
   ```

5. **Run the application**
   ```bash
   python main.py
   ```

   Or using uvicorn directly:
   ```bash
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

6. **Access the API**
   - API: http://localhost:8000
   - Interactive docs: http://localhost:8000/docs
   - Health check: http://localhost:8000/health

## Environment Variables

Create a `.env` file in the backend directory with the following variables:

```env
# Security
SECRET_KEY=your-super-secret-key-here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Database
DATABASE_URL=sqlite:///./bluewall.db

# Server
HOST=0.0.0.0
PORT=8000
```

## API Endpoints

### Authentication
- `POST /login` - User login with username, password, and TOTP

### Admin Routes (Admin only)
- `GET /admin/system-info` - System information

### Officer Routes (Officer + Admin)
- `GET /officer/monitoring` - Monitoring data

### User Routes (Authenticated users)
- `GET /user/profile` - Current user profile

### Public Routes
- `GET /` - API information
- `GET /health` - Health check

## Authentication Flow

1. **Login Request**
   ```json
   POST /login
   {
     "username": "admin",
     "password": "admin123",
     "totp_code": "123456"
   }
   ```

2. **Success Response**
   ```json
   {
     "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
     "token_type": "bearer",
     "role": "admin",
     "username": "admin"
   }
   ```

3. **Use Token**
   ```
   Authorization: Bearer <access_token>
   ```

## Default Admin User

On first run, a default admin user is created:
- **Username**: `admin`
- **Password**: `admin123`
- **Role**: `admin`

**⚠️ IMPORTANT**: Change these credentials immediately after first login!

## Database

### SQLite (Default)
- File: `bluewall.db`
- No additional setup required
- Suitable for development and small deployments

### PostgreSQL
```env
DATABASE_URL=postgresql://username:password@localhost:5432/bluewall_db
```

### MySQL
```env
DATABASE_URL=mysql+pymysql://username:password@localhost:3306/bluewall_db
```

## Docker

### Build and Run
```bash
# Build the image
docker build -f Dockerfile.backend -t bluewall-backend .

# Run the container
docker run -p 8000:8000 --env-file .env bluewall-backend
```

### Docker Compose
```yaml
version: '3.8'
services:
  backend:
    build:
      context: .
      dockerfile: Dockerfile.backend
    ports:
      - "8000:8000"
    env_file:
      - .env
    volumes:
      - ./logs:/app/logs
      - ./uploads:/app/uploads
```

## Development

### Code Style
- Follow PEP 8 guidelines
- Use type hints
- Include docstrings for all functions
- Run linting: `flake8 .`

### Testing
```bash
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run tests
pytest
```

### Database Migrations
```bash
# Install Alembic
pip install alembic

# Initialize migrations
alembic init alembic

# Create migration
alembic revision --autogenerate -m "Initial migration"

# Apply migrations
alembic upgrade head
```

## Security Features

- **Password Hashing**: Bcrypt with salt
- **JWT Tokens**: Secure, time-limited access tokens
- **TOTP**: Two-factor authentication
- **Role-Based Access**: Granular permission control
- **Input Validation**: Pydantic models for request validation
- **CORS Protection**: Configurable cross-origin settings

## Production Deployment

### Environment
- Use strong, unique `SECRET_KEY`
- Configure proper `DATABASE_URL`
- Set `ACCESS_TOKEN_EXPIRE_MINUTES` appropriately
- Enable HTTPS in production

### Server
- Use Gunicorn with Uvicorn workers
- Configure reverse proxy (Nginx/Apache)
- Set up SSL/TLS certificates
- Configure logging and monitoring

### Security
- Change default credentials
- Use environment variables for secrets
- Regular security updates
- Monitor access logs

## Troubleshooting

### Common Issues

1. **Import Errors**
   - Ensure virtual environment is activated
   - Check all dependencies are installed

2. **Database Connection**
   - Verify `DATABASE_URL` format
   - Check database server is running

3. **TOTP Issues**
   - Ensure system clock is accurate
   - Check TOTP secret is properly generated

4. **Permission Errors**
   - Check file permissions
   - Ensure proper user/group ownership

### Logs
- Check application logs for detailed error messages
- Enable debug logging by setting `LOG_LEVEL=DEBUG`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

[Add your license information here]

## Support

For issues and questions:
- Create an issue in the repository
- Check the documentation
- Review the code examples

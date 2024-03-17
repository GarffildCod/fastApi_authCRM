from pydantic import BaseModel, Field, EmailStr, SecretStr, validator
import re

def validate_password(password: SecretStr):
    pattern = r'^(?=.*[A-Za-z])(?=.*\d).{6,100}$'
    password_value = password.get_secret_value()
    if not re.match(pattern, password_value):
        raise ValueError('Пароль должен содержать не менее 6 символов, включая буквы и цифры')
    return password

class SUserAuth(BaseModel):
    username: str
    email: EmailStr
    password: SecretStr

    # Валидация пароля
    @validator('password', pre=True)
    def validate_password(cls, v):
        return validate_password(v)


    # class Config:
    #     orm_mode = True

# модели сброса пароля пользователя
class SUserPasswordReset(BaseModel):
    email: EmailStr = Field(..., description="Email address of the user")
    old_password: SecretStr = Field(..., description="Old password of the user")
    new_password: SecretStr = Field(..., description="New password of the user")
    confirm_password: SecretStr = Field(..., description="Confirmation of the new password")

    # чтобы новый пароль и подтверждение пароля совпадали
    @validator('confirm_password')
    def passwords_match(cls, v, values, **kwargs):
        if 'new_password' in values and v.get_secret_value() != values['new_password'].get_secret_value():
            raise ValueError('Пароли не совпадают')
        return v

    #  пароль
    @validator('new_password', 'old_password')
    def validate_password(cls, v):
        return validate_password(v)

    class Config:
        schema_extra = {
            "example": {
                "email": "user@example.com",
                "old_password": "old_password",
                "new_password": "new_password",
                "confirm_password": "new_password",
            }
        }
# password_utils.py
import bcrypt

class PasswordHasher:
    def __init__(self, rounds: int = 12):
        if not (4 <= rounds <= 31):
            raise ValueError("rounds must be between 4 and 31")
        self.rounds = rounds

    def hash(self, password: str) -> str:
        """把明文密码变成哈希字符串"""
        if not password:
            raise ValueError("Password cannot be empty")
        if len(password.encode('utf-8')) > 72:
            raise ValueError("Password too long")
        salt = bcrypt.gensalt(rounds=self.rounds)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def verify(self, password: str, hashed: str) -> bool:
        """检查密码是否和哈希匹配"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except Exception:
            return False
import jwt
from datetime import datetime, timedelta, timezone
import bcrypt


class JWTHandler:
    def __init__(self, secret_key: str, algorithm: str = "HS256", expire_minutes: int = 30):
        """
        :param secret_key: 密钥
        :param algorithm: 签名算法
        :param expire_minutes: Token 有效期（分钟）
        """
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.expire_minutes = expire_minutes
    
    def create_access_token(self, subject: str, payload: dict | None = None) -> str:
        """
        生成 JWT 访问令牌
        
        :param subject: 通常是用户 ID 或用户名（放在 'sub' 字段）
        :param payload: 额外声明（如 rolse, email）等
        :retuen: JWT 字符串
        """
        if payload is None:
            payload = {}
        now = datetime.now(timezone.utc)
        expire = datetime.now() + timedelta(minutes=self.expire_minutes)

        to_encode = {
            "sub": subject,
            "exp": expire,
            "iat": now,
            **payload
        }

        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token: str) -> dict | None:
        """
        验证并解码 JWT
        :return: 载荷字典（如果有效），否则 None
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm]
            )
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        
class HashHandler:
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